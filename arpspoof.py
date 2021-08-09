#!/usr/bin/env python3

import logging
logging.getLogger("scapy").setLevel(logging.WARNING)

from scapy.all import *
from concurrent import futures
from collections import namedtuple, Counter
import argparse
import functools
import threading
import time

logger = logging.getLogger('arpspoof')

ARPSnifferContext = namedtuple('ARPSnifferContext', ('trusted_arp_table', 'pinging', 'ongoing_sessions', 'ongoing_probings', 'ping_tasks', 'l2ping', 'prn_lock', 'probings_lock', 'pinging_lock', 'us'))

def parse_loglevel(level):
    try:
        level = int(level)
    except ValueError:
        pass
    return level

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-l', '--log-level', default='INFO', type=parse_loglevel, help='Set log level (either Python log level names e.g. DEBUG or numbers e.g. 10).')
    p.add_argument('-s', '--scapy-log-level', default='WARNING', type=parse_loglevel, help="Set Scapy's log level.")
    p.add_argument('-i', '--interface', help='Use specified interface.')
    p.add_argument('-p', '--l2ping-type', default='tcp', help='Specify layer 2 ping type (tcp or icmp). By default tcp is used as it is also used by Ramachandran, et al in the original paper.')
    return p, p.parse_args()

def check_task_for_exception(fut):
    try:
        fut.result()
    except Exception:
        logger.exception('Exception in %s', fut)

def l2ping(dhwaddr, daddr):
    pkt = Ether(dst=dhwaddr) / IP(dst=daddr) / ICMP()
    return srp1(pkt, timeout=2)

def l2tcping(dhwaddr, daddr, dport=1337):
    pkt = Ether(dst=dhwaddr) / IP(dst=daddr) / TCP(dport=dport, flags="S")
    return srp1(pkt, timeout=2)

def arping_multi(pdst):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=pdst)
    return srp(pkt, timeout=2, multi=True)

# Same as arping_multi but with the pinging attempt recorded so we can ignore these packets temporarily.
def arping_multi_recorded_probing(ctx, pdst):
    # Adding is atomic.
    ctx.ongoing_probings[pdst] += 1
    ans, unans = arping_multi(pdst)
    # This is non-atomic, acquire the lock before proceeding.
    with ctx.probings_lock:
        ctx.ongoing_probings[pdst] -= 1
        if ctx.ongoing_probings[pdst] <= 0:
            del ctx.ongoing_probings[pdst]
    return ans, unans

def test_for_real_host(ctx, task_descs):
    # This can be speed up by parallelize the probing or by implementing an l2ping variant that supports multiple targets.
    detected_real_host = None
    multiple_host_replied = False
    for hwaddr, addr, _reason in task_descs:
        ans = ctx.l2ping(hwaddr, addr)
        if detected_real_host is None and not multiple_host_replied:
            detected_real_host = ans
        elif detected_real_host is not None:
            multiple_host_replied = True
            detected_real_host = None
    if detected_real_host:
        real_hwaddr, real_addr = detected_real_host
        logger.warning('Most probable real host: %s (%s)', real_addr, real_hwaddr)
    elif multiple_host_replied:
        logger.warning('Multiple hosts responded to the layer 2 ping. Unable to detect the real host.')
    else:
        logger.warning('No host responded to the layer 2 ping. Unable to detect the real host.')
        
# TODO
def on_detect_new_arp_source(ctx, task_desc):
    hwaddr, addr, _reason = task_desc
    if ctx.trusted_arp_table.get(addr) == hwaddr:
        logger.debug('Skipping trusted host %s (%s)', addr, hwaddr)
    else:
        # Issue layer 2 ping and check if host is responsive (i.e. actually using this IP address).
        ans = ctx.l2ping(hwaddr, addr)
        if ans is None:
            logger.warning('Host %s (%s) did not respond to layer 2 ping. Possible spoofing event.', addr, hwaddr)
        else:
            # Optionally, also use ARP ping here
            # if ...:
            # else:
            # Add to trusted table
            logger.info('Adding %s (%s) to trusted ARP table.', addr, hwaddr)
            ctx.trusted_arp_table[addr] = hwaddr

    logger.debug('on_detect_new_arp_source(): Cleaning up task %s', task_desc)
    with ctx.pinging_lock:
        del ctx.pinging[task_desc]

def on_new_response_half_cycle(ctx, task_desc):
    hwaddr, addr, _reason = task_desc
    logger.debug('on_new_response_half_cycle(): from %s (%s)', addr, hwaddr)

    ans, _unans = arping_multi_recorded_probing(ctx, addr)
    nans = len(ans)
    logger.debug('on_new_response_half_cycle(): Received %d ARP ping responses', nans)
    if nans == 0:
        logger.warning('Unsolicited, unverifiable ARP response from %s (%s) found. Possible spoofing event.', addr, hwaddr)
    elif nans == 1:
        ans = ctx.l2ping(hwaddr, addr)
        if ans is None:
            logger.warning('Host %s (%s) sent an unsolicited ARP response and did not respond to layer 2 ping. Possible spoofing event.', addr, hwaddr)
        else:
            logger.info('Adding %s (%s) to trusted ARP table.', addr, hwaddr)
    else:
        logger.warning('Host %s (%s) sent an unsolicited ARP response and multiple hosts responded to the ARP ping. Possible spoofing event.', addr, hwaddr)
        logger.warning('Attempting to detect real host...')
        test_for_real_host(ctx, tuple((a.answer[ARP].hwsrc, a.answer[ARP].psrc, 'arping_multi') for a in ans))
    logger.debug('on_new_response_half_cycle(): Cleaning up task %s', task_desc)
    with ctx.pinging_lock:
        del ctx.pinging[task_desc]

# /TODO

def add_ping_job(ctx, task_desc, func, *args, **kwargs):
    with ctx.pinging_lock:
        if task_desc not in ctx.pinging:
            logger.debug('add_ping_job(): Dispatching task %s', task_desc)
            ctx.pinging[task_desc] = task = ctx.ping_tasks.submit(func, ctx, task_desc, *args, **kwargs)
            task.add_done_callback(check_task_for_exception)

def add_ping_jobs(ctx, task_descs, func, *args, **kwargs):
    # multiple ping target
    for task_desc in task_descs:
        add_ping_job(ctx, task_desc, func, *args, **kwargs)

def on_arp_session_timeout(ctx, session_id):
    session = ctx.ongoing_sessions[session_id]

    ans = session['ans']
    nans = len(ans)
    hwinit, pinit, _ = session_id
    logger.debug('ARP session time out. Testing initiator %s (%s).', pinit, hwinit)
    task_desc = (hwinit, pinit, 'new_arp_source')
    add_ping_job(ctx, task_desc, on_detect_new_arp_source)
    if nans == 1:
        # Full Cycle - Single response
        logger.debug('Full cycle. Testing responder %s (%s).', ans[0][ARP].psrc, ans[0][ARP].hwsrc)
        task_desc = (ans[0][ARP].hwsrc, ans[0][ARP].psrc, 'new_arp_source')
        add_ping_job(ctx, task_desc, on_detect_new_arp_source)
    elif nans > 1:
        # Full Cycle - Multiple response
        task_descs = tuple((a[ARP].hwsrc, a[ARP].psrc, 'full_cycle_multi') for a in ans)
        #add_ping_jobs(ctx, task_descs, on_new_full_cycle)
        hwsrc, psrc, pdst = session_id
        logger.warning('Multiple hosts responded to a single ARP request (%s (%s) -> %s). Possible spoofing event.', psrc, hwsrc, pdst)
        logger.warning('Attempting to detect real host...')
        # TODO how do we manage the tasks for real host testing?
        test_for_real_host(ctx, task_descs)

    # Remove this session as it's already processed
    del ctx.ongoing_sessions[session_id]

def on_arp_packet_received(ctx, pkt):
    # TODO we won't need this if prn is not multithreaded. Is it multithreaded?
    with ctx.prn_lock:
        if ARP in pkt and Ether in pkt and pkt[ARP].op in (1, 2): 
            arp = pkt[ARP]
            eth = pkt[Ether]
            if arp.op == 1: # who-has
                logger.debug('%s -> %s: Who has %s? Tell %s (%s).', eth.src, eth.dst, arp.pdst, arp.psrc, arp.hwsrc)
            elif arp.op == 2: # is-at
                logger.debug('%s <- %s: Reply to %s (%s): %s is at %s.', eth.dst, eth.src, arp.pdst, arp.hwdst, arp.psrc, arp.hwsrc)
                # MAC-ARP Header Anomaly Detector - destination
                if arp.hwdst != eth.dst:
                    logger.warning('Inconsistent Ether destination (%s) and ARP destination (%s). Possible spoofing event.', eth.dst, arp.hwdst)
                    return
            # MAC-ARP Header Anomaly Detector - source
            if arp.hwsrc != eth.src:
                logger.warning('Inconsistent Ether source (%s) and ARP source (%s). Possible spoofing event.', eth.src, arp.hwsrc)
                return

            # Known Traffic Filter
            trusted_hwsrc, trusted_hwdst = ctx.trusted_arp_table.get(arp.psrc), ctx.trusted_arp_table.get(arp.pdst)
            logger.debug('Source %s has known hwaddr %s (got %s), dest %s has known hwaddr %s (got %s)', arp.psrc, trusted_hwsrc, arp.hwsrc, arp.pdst, trusted_hwdst, arp.hwdst)
            us_hwaddr, us_addr = ctx.us

            if trusted_hwsrc == arp.hwsrc and (arp.op == 1 or (arp.op == 2 and trusted_hwdst == arp.hwdst)):
                logger.debug('Trusted traffic.')
                return
            elif trusted_hwsrc is not None and (arp.op == 1 or (arp.op == 2 and trusted_hwdst is not None)):
                logger.warning('Contradicting ARP update found. Possible spoofing event.')
                return

            # Ensure ongoing_probings is completely written
            with ctx.probings_lock:
                if (arp.op == 1 and arp.hwsrc == us_hwaddr and arp.psrc == us_addr and arp.pdst in ctx.ongoing_probings) or \
                        (arp.op == 2 and arp.hwdst == us_hwaddr and arp.pdst == us_addr and arp.psrc in ctx.ongoing_probings):
                    logger.debug('Ignore ARP ping sessions initiated by us.')
                    return

            # Spoof Detection Engine - session tracking
            if arp.op == 1:
                session_id = (arp.hwsrc, arp.psrc, arp.pdst)
                # Track this session
                if session_id not in ctx.ongoing_sessions:
                    logger.debug('Tracking new session %s.', session_id)
                    # Hard-code timeout to 2 for now
                    timer = threading.Timer(2, on_arp_session_timeout, args=(ctx, session_id))
                    ctx.ongoing_sessions[session_id] = {
                        'type': 'track',
                        'on_timeout': timer,
                        'ans': [],
                    }
                    timer.start()
                    logger.debug('Tracked.')
            elif arp.op == 2:
                session_id = (arp.hwdst, arp.pdst, arp.psrc)
                if session_id not in ctx.ongoing_sessions:
                    # Response Half Cycle
                    logger.debug('Response half cycle detected. Verifying...')
                    task_desc = (arp.hwsrc, arp.psrc, 'response_half_cycle')
                    add_ping_job(ctx, task_desc, on_new_response_half_cycle)
                    logger.debug('Verification job dispatched.')
                else:
                    # Collect responses
                    logger.debug('Full cycle detected.')
                    ctx.ongoing_sessions[session_id]['ans'].append(pkt)

def sniff_arp_sessions(iface=None, l2ping_type='tcp'):
    conf.verb = 0
    if iface is not None:
        logger.debug('Using interface %s', iface)
        conf.iface = iface
    else:
        logger.debug('Using interface %s', conf.iface)

    trusted_arp_table = {}
    pinging = {}
    # (hwinit, pinit, ptarg): last_request_at
    ongoing_sessions = {}
    ongoing_probings = Counter()
    ping_tasks = futures.ThreadPoolExecutor()
    try:
        l2ping_impl = {'tcp': l2tcping, 'icmp': l2ping}[l2ping_type]
    except KeyError:
        raise ValueError(f'Invalid layer 2 ping type "{l2ping_type}"')
    ctx = ARPSnifferContext(trusted_arp_table, pinging, ongoing_sessions, ongoing_probings, ping_tasks, l2ping_impl, threading.RLock(), threading.RLock(), threading.RLock(), (get_if_hwaddr(conf.iface), get_if_addr(conf.iface)))

    # Whitelist ourselves
    trusted_arp_table[get_if_addr(conf.iface)] = get_if_hwaddr(conf.iface)

    # Start sniffing
    sniff_result = sniff(filter='arp', store=False, prn=functools.partial(on_arp_packet_received, ctx))

if __name__ == '__main__':
    p, args = parse_args()
    logging.basicConfig(level=args.log_level, format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s')
    logging.getLogger("scapy").setLevel(args.scapy_log_level)
    sniff_arp_sessions(args.interface, args.l2ping_type)
