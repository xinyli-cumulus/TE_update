#!/usr/bin/env python3
"""Turbo-Entabulator detections."""

# Copyright(c) 2018, 2019 Cumulus Networks, Inc
# John Fraizer <jfraizer@cumulusnetworks.com>

import glob
import gzip
import ipaddress
import os
import re
import sys
from distutils.version import StrictVersion
from turbo_entabulator.utilities import check_dependencies
from turbo_entabulator.m_logger import logger


def detect_3ie3_3me3_discard(deprecated, satisfied, discovered, problems,
                             warnings):
    """
    Detect 3IE3/3ME3/3IE4 drives that do not have 'discard' option enabled.

    We need to know if the drive should be suspect based on model.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_etc', 'detect_log_sigs']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    page_mode_drive = False
    for warning in warnings:
        if '3IE3/3ME3' in warning:
            page_mode_drive = True
    if page_mode_drive:
        logger.debug(
            'Found warning for 3IE3/3ME3/3IE4 drive.  Analyzing fstab.')
        if 'fstab' not in discovered:
            msg = ('3IE3/3ME3/3IE4 drive found but fstab not available for '
                   'analysis!  Please verify that drive is mounted with '
                   'discard option on / mount-point.')
            logger.debug(msg)
            problems.append(msg)
        else:
            mountpoints = []
            for mount in discovered['fstab']:
                logger.debug(mount)
                if '/ ' in mount and 'discard' not in mount:
                    mountpoint = mount.split()[1]
                    logger.debug(mountpoint)
                    mountpoints.append(mountpoint)
            if len(mountpoints) > 0:
                msg = ('3IE3/3ME3/3IE4-DISCARD: Mount point(s) {} found '
                       'mounted without the discard option!  See '
                       'http://tinyurl.com/y5evad7y'
                       .format(mountpoints))
                problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_arp_mac_timers_mismatch(deprecated, satisfied, bridges, interfaces,
                                   timers, problems):
    """
    Detect when timers are mismatched and could cause problems.

    # Detect if the ARP timeout is longer than any of the configured bridge FDB
    # MAC timeout.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_sysctl', 'discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if ('sysctl' in timers and 'net.ipv4.neigh.default.base_reachable_time_ms'
            in timers['sysctl']):
        arp_timeout = (
            timers['sysctl']['net.ipv4.neigh.default.base_reachable_time_ms']
            / 1000)
    else:
        logger.debug("[{}] not detected. Skipping"
                     .format('net.ipv4.neigh.default.base_reachable_time_ms'))
        return(satisfied, problems)
    for bridge in bridges:
        if ('bridge-ageing' in interfaces[bridge]):
            mac_timeout = interfaces[bridge]['bridge-ageing']
        else:
            mac_timeout = 1800
        if (int(mac_timeout) <= int(arp_timeout)):
            msg = ("MAC-TIMEOUT-MISCONFIG: Bridge [{}] MAC timeout value [{}]"
                   "secs is <= than ARP timeout [{}]secs"
                   .format(bridge, mac_timeout, arp_timeout))
            logger.debug(msg)
            problems.append(msg)
    satisfied.append(name)
    return(satisfied, problems)


def detect_bad_gport(deprecated, satisfied, discovered, problems):
    """
    Detect bad GPORT programming.

    #
    # This function uses the following which are all stored in discovered{}...
    #
    # *> [2]:[0]:[0]:[48]:[00:60:16:99:6e:25]:[32]:[10.37.146.81]
    #                    10.37.254.34                           0 4219750110 4219750211 i #noqa
    #                    RT:18243:72146 RT:18243:379999 ET:8 Rmac:44:38:39:ff:00:18 #noqa
    # Becomes...
    # "evpn_routes": {
    #         "10.37.146.81/32": {
    #                     "nexthop": "10.37.254.34",
    #                     "type": "2"
    #         },
    #
    #
    # #     VRF     Net addr             Next Hop Mac        INTF MODID PORT PRIO CLASS HIT VLAN #noqa
    # 704   13       10.37.146.81/32      00:00:00:00:00:00 457630    0     0     0    0 n #noqa
    # Becomes...
    # "l3.defip": {
    #           "13": {
    #               "10.37.146.81/32": "457630",
    #               },
    #
    # Entry  Mac                 Vlan INTF PORT MOD MPLS_LABEL ToCpu Drop RefCount L3MC #noqa
    # 457630  44:38:39:ff:00:18    0 14419   204    0        -1   no   no   33   no #noqa
    # Becomes...
    # "l3.egress": {
    #           "457630": {
    #                     "port": 204,
    #                     "gport": "0x800000cc"
    #                     },
    # gport: 0x800000cc; vpn: (28673/0x7001); eg_if: 202304; f: 0x985 class_id: 2 #noqa
    #   match_tun: 0x4c00000f; egress_tun: 0x4c00000d
    # Becomes...
    # "gports": {
    #         "0x800000cc": {
    #                     "match_tun": "0x4c00000f",
    #                     "egress_tun": "0x4c00000d"
    #         },
    #
    # init_id: 0x4c00000d; term_id: 0x4c00000f; sip: 10.37.254.34; dip: 10.37.254.48 #noqa
    # Becomes...
    # "tunnels": {
    #          "0x4c00000d_0x4c00000f": {
    #                                 "init_id": "0x4c00000d",
    #                                 "term_id": "0x4c00000f",
    #                                 "sip": "10.37.254.34",
    #                                 "dip": "10.37.254.48"
    #         },
    #
    # The detection uses the following logic:
    #
    # (1) Iterate through evpn_routes storing the nexthop as a variable to
    #     compare.
    # (2) Look up matching entry(s) in l3.defip and for each match, use the
    #     value to match to the corresponding entry in l3.egress and its
    #     gport.
    # (3) Look up the gport in gports and use its egress_tun + match_tun to
    #     build a string to look up a corresponding tunnel in tunnels.
    # (4) Compare the SIP to the nexthop that was stored in step #1.  If it
    #     doesn't match, that is an indication of bad GPORT programming since
    #     the nexthop value comes from the kernel side but the SIP entry comes
    #     from hardware.
    #
    # Simple, huh?
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_evpn_routes', 'discover_l3_defip', 'discover_l3_egress',
            'discover_vxlan_info']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    # Discovery bad GPORT programming.
    #
    no_match = []
    matches = []
    for route in discovered['evpn_routes']:
        # Store the nexthop for comparrison.
        nexthop = discovered['evpn_routes'][route]['nexthop']
        # logger.debug(route)

        # If we find a matching route in l3.defip, we will use it to find
        # the gport associated with the 'INTF' entry in l3.egress.
        gport = False
        for vrf in discovered['l3.defip']:
            if route in discovered['l3.defip'][vrf]:
                intf = discovered['l3.defip'][vrf][route]
                matches.append(intf)
                gport = discovered['l3.egress'][intf]['gport']
        if not gport:
            logger.debug('No l3.defip match found for {}'
                         .format(route))
            no_match.append(route)
            continue

        # If we're here, we've found a match in l3.defip and have a gport.
        logger.debug('Found GPORT: {} for EVPN route: {}'.format(gport, route))

        # If we don't have a matching GPORT, that is probably a problem.
        if gport not in discovered['gports']:
            msg = ('NO-GPORT: l3.egress entry for EVPN route [{}] points to '
                   'nonexistent GPORT [{}]!'.format(route, gport))
            logger.debug(msg)
            problems.append(msg)
            continue

        # If we're here, we have a matching GPORT entry so we can look up
        # the associated tunnel.
        egress_tun = discovered['gports'][gport]['egress_tun']
        match_tun = discovered['gports'][gport]['match_tun']
        # Build our tunnel index by combining egress_tun and match_tun from the
        # GPORT.
        tunnel = egress_tun + '_' + match_tun

        # Look up our SIP inn the associated tunnel so we can compare it to
        # the nextop from the EVPN route.
        SIP = discovered['tunnels'][tunnel]['sip']
        if SIP != nexthop:
            msg = ('BAD-GPORT: Programmed gport [{}] for EVPN route {} has '
                   'wrong SIP: [{}]. Should be [{}].'
                   .format(gport, route, SIP, nexthop))
            logger.debug(msg)
            problems.append(msg)

    logger.debug(
        'Found l3.defip match for {} evpn routes...'.format(len(matches)))
    logger.debug('No match in l3.defip for {} routes...'.format(len(no_match)))
    #
    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_bad_sysclock(deprecated, satisfied, discovered, problems):
    """Detect if the system clock has a date prior to the kernel build date."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_kernel', 'discover_date']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if ('kernel date' not in discovered) or ('system date' not in discovered):
        logger.debug('Date information is not complete.  No compare possible!')
        return(satisfied, problems)

    kernel = re.sub('-', '', discovered['kernel date'])
    system = re.sub('-', '', discovered['system date'])
    diff = int(system) - int(kernel)
    if diff < 0:
        msg = ('BAD-CLOCK: System date [{}] is earlier than kernel build date '
               '[{}]! This *will* cause problems! See CM-24846'
               .format(discovered['system date'], discovered['kernel date']))
        logger.debug(msg)
        problems.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_broken_cl(deprecated, satisfied, discovered, problems):
    """Detect when switch is running known broken versions of CL."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_etc']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if 'lsb-release' not in discovered:
        logger.debug("Don't have lsb-release.  Can't compare!")
        return(satisfied, problems)

    broken_versions = ['3.7.4', '3.7.9']
    hints = {}
    hints['3.7.4'] = ('BROKEN-VERSION: Switch is running CL 3.7.4 which has '
                      'been pulled from public circulation. See: CM-24495, '
                      'CM-23829, CM-24043, CM-24508')
    hints['3.7.9'] = ('BROKEN VERSION: CL 3.7.9 suffers from CM-26383. '
                      'CPU generated traffic egresses access ports with a '
                      '802.1Q tag with a vlan ID of 0')

    # Look for broken version.
    for version in broken_versions:
        if version in discovered['lsb-release']:
            msg = hints[version]
            logger.debug(msg)
            problems.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_bcm_counters(deprecated, satisfied, bcm_counters, portmap,
                        warnings):
    """
    Warn on certain BCM counters.

    # Iterate through the list of counters we care about and warn if we have
    # discovered any interfaces that show those counters.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_portmap', 'discover_bcm_counters']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Counters we care about:
    counters = ['TDBGC5', 'TERR', 'RFRG', 'RFCS', 'RERPKT', 'MTUE']
    # Iterate through the list of counters in bcm_counters...
    for counter in bcm_counters:
        # If this is one we care about (why would we discover it if we didn't?)
        if counter in counters:
            # iterate through all interfaces in that counter and warn.
            for iface in bcm_counters[counter]:
                if iface in portmap:
                    msg = ('BCM-COUNTER-WARNING: Interface [{} - ({})] : [{}]'
                           ' = {}'
                           .format(portmap[iface], iface, counter,
                                   bcm_counters[counter][iface]))
                else:
                    msg = ('BCM-COUNTER-WARNING: Interface [{}] : [{}]'
                           ' = {}'
                           .format(iface, counter,
                                   bcm_counters[counter][iface]))
                logger.debug(msg)
                warnings.append(msg)
    satisfied.append(name)
    return(satisfied, warnings)


def detect_clagd_issues(deprecated, satisfied, addresses, bridges, features, # noqa
                        interfaces, problems, v4_routes, warnings):
    """Detect clagd issues."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems, warnings)
    reqs = ['discover_clagd', 'discover_v4_routes']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems, warnings)
    # Look for peerlink to be member of at least one bridge.
    if 'clag' not in features:
        return(satisfied, problems, warnings)
    # Check if peer is detected as alive:
    if 'peer-alive' in features['clag']:
        if 'True' not in features['clag']['peer-alive']:
            msg = ("CLAGD-PEER-ALIVE: The 'alive' status of the clag peer is "
                   "'{}'!"
                   .format(features['clag']['peer-alive']))
            logger.debug(msg)
            problems.append(msg)

    # check for enabled debugs for clag
    if (features['clag'].get("debug", "0x0") != "0x0"):
        msg = ("CLAG-DEBUG: Clag debug enabled and is set to {}"
                .format(features['clag'].get("debug", "0x0")))
        logger.debug(msg)
        warnings.append(msg)

    # Check if traffic indirect feature is enabled
    if 'redirectEnable' in features['clag']:
        logger.debug("redirectEnable value {}"
                     .format(features['clag']['redirectEnable']))
        if features['clag']['redirectEnable'] == 'True':
            msg = ('CLAG-INDIRECT: CLAG traffic indirect feature is enabled!')
            logger.debug(msg)
            warnings.append(msg)

    if 'peerlink' in features['clag']:
        parent = features['clag']['peerlink'].split('.')[0]
        parent_member = []
        # sub_member = []
        logger.debug(bridges)
        for bridge in bridges:
            logger.debug(interfaces[bridge])
            # parent_found = False
            sub_found = False
            if 'bridge-ports' not in interfaces[bridge]:
                continue
            if parent in interfaces[bridge]['bridge-ports']:
                # parent_found = True
                parent_member.append(bridge)
            if (features['clag']['peerlink'] in
                    interfaces[bridge]['bridge-ports']):
                sub_found = True
            # Its an issue if the clag peerlink subinterface is a member
            # of a bridge.
            if sub_found:
                msg = ('PEERLINK-ISSUE: Peerlink interface [{}] is member of '
                       'bridge [{}] !'
                       .format(features['clag']['peerlink'], bridge))
                logger.debug(msg)
                problems.append(msg)
            # Its an issue if both the parent and subint are a member of the
            # same bridge!
        #    if parent_found and sub_found:
        #        msg = ('PEERLINK-ISSUE: Peerlink interface [{}] found in same'
        #               ' bridge [{}] as parent [{}]!'
        #               .format(features['clag']['peerlink'], bridge, parent))
        #        logger.debug(msg)
        #        problems.append(msg)
        # If the parent is not a member of any bridge, that's an issue!
        if len(parent_member) < 1:
            msg = ('PEERLINK-ISSUE: Peerlink parent interface [{}] is not'
                   ' a member of any bridge!'
                   .format(parent))
            logger.debug(msg)
            problems.append(msg)
        # If the parent is a member of more than one bridge, that's an issue!
        if len(parent_member) > 1:
            msg = ('PEERLINK-ISSUE: Peerlink parent interface [{}] is member'
                   ' of more than one bridge {} !'
                   .format(parent, parent_member))
            logger.debug(msg)
            problems.append(msg)
    # Check if clahd-backup-ip is reachable.
    if 'clagd-backup-ip-status' in features['clag']:
        # If status is active, we're all good.
        if features['clag']['clagd-backup-ip-status'] == 'active':
            logger.debug('clagd-backup-ip-status is ACTIVE. No check needed.')
            satisfied.append(name)
            return(satisfied, problems, warnings)
        else:
            msg = ('CLAG-BACKUP-IP-STATUS: The status of the clagd-backup-ip '
                   'is [{}]!'
                   .format(features['clag']['clagd-backup-ip-status']))
            logger.debug(msg)
            warnings.append(msg)
    # Determine which VRF the clagd-backup-ip is configured for.
    if 'clagd-backup-ip' not in features['clag']:
        msg = ('NO-CLAGD-BACKUP-IP: No Backup-IP configured for CLAG!')
        logger.debug(msg)
        warnings.append(msg)
        satisfied.append(name)
        return(satisfied, problems, warnings)
    if 'vrf' in features['clag']['clagd-backup-ip']:
        clagd_backup_ip, vrf = (
            features['clag']['clagd-backup-ip'].split('vrf'))
        clagd_backup_ip = clagd_backup_ip.rstrip()
        vrf = vrf.strip()
    else:
        clagd_backup_ip = features['clag']['clagd-backup-ip']
        vrf = 'default'
    # Verify that the backup IP is a valid IP address!
    try:
        raw = ipaddress.ip_address(clagd_backup_ip)
        logger.debug('Valid clagd-backup-ip [{}] found.'.format(raw))
    except: # noqa
        msg = ('CLAGD-ERROR: clagd-backup-ip [{}] on appears to be '
               'invalid!'.format(clagd_backup_ip))
        logger.debug(msg)
        problems.append(msg)
        satisfied.append(name)
        return(satisfied, problems, warnings)
    # Iterate each L3/subnet found in the vrf and check if
    # clagd-backup-ip falls in any of these subnets
    local_interf = False
    default = False
    if vrf not in v4_routes:
        logger.debug('VRF [{}] does not exist in v4_routes!'.format(vrf))
    else:
        for subnet in v4_routes[vrf]:
            # If clagd-backup-ip in a subnet,
            # set found flag and continue
            if '0.0.0.0/0' in subnet:
                default = True
                continue
            if (ipaddress.ip_address(clagd_backup_ip) in
               ipaddress.ip_interface(subnet).network):
                local_interf = True
                break
    # If no matching local subnet was found, add warning message.
    if not local_interf and not default:
        msg = ("CLAGD-BACKUP-IP-UNREACHABLE: No local route to "
               "clagd-backup-ip [{}] in vrf [{}]!"
               .format(clagd_backup_ip, vrf))
        logger.debug(msg)
        warnings.append(msg)
    if not local_interf and default:
        msg = ("CLAGD-BACKUP-IP-NOT-LOCAL: No local route to "
               "clagd-backup-ip [{}] in vrf [{}] but reachable via default "
               "route."
               .format(clagd_backup_ip, vrf))
        logger.debug(msg)
        warnings.append(msg)
    # Detect if the clagd-backup-ip is our own address!
    for int in addresses:
        if clagd_backup_ip in addresses[int]:
            msg = ('CONFIG-ERROR: Configured clagd-backup-ip [{}] is our '
                   'own address on interface [{}]!'
                   .format(clagd_backup_ip, int))
            logger.debug(msg)
            problems.append(msg)

    satisfied.append(name)
    return(satisfied, problems, warnings)


def detect_cm26383(deprecated, satisfied, discovered, interfaces, problems): # noqa
    """Detect conditions where CM-26383 would come into play."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_etc', 'discover_ifquery', 'discover_dpkg']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    viable = False
    # If this isn't a Broadcom switch running version 6.5.14-cl3u25 of bcm-sdk
    # it isn't going to hit CM-26383. No need to check.
    if 'packages' in discovered:
        if 'bcm-sdk'in discovered['packages']:
            if discovered['packages']['bcm-sdk']['version'] == '6.5.14-cl3u25':
                viable = True
    if not viable:
        logger.debug("Check not applicable to this package release. Skipping"
                     .format(name))
        return(satisfied, problems)
    # We only care if we're older than 3.7.10
    min_version = '3.7.10'
    if 'lsb-release' not in discovered:
        logger.debug("Don't have lsb-release.  Can't compare!")
        return(satisfied, problems)
    this_version = discovered['lsb-release']
    if StrictVersion(min_version) <= StrictVersion(this_version):
        logger.debug("We don't check for CM-26383 on code prior to 3.7.10.")
        return(satisfied, problems)
    # We need a couple of lists to store any interfaces (bonds or physical swp
    # interfaces) that have bridge-access or bridge-pvid configured. We will
    # store them separately because it gives more detailed reporting and its
    # computationally cheap to do it.
    ba = []
    bpv = []
    # We're only interested in physical interfaces or their bond parents.
    # We don't care about bridges or VNIs which may have bridge-pvid or
    # bridge-access.
    for iface in interfaces:
        if 'vxlan-id' in interfaces[iface]:
            continue
        if 'is-bridge' in interfaces[iface]:
            continue
        if 'bridge-access' in interfaces[iface]:
            ba.append(iface)
        if 'bridge-pvid' in interfaces[iface]:
            bpv.append(iface)
    # Time for some reporting on our findings - if any...
    if len(ba) > 0:
        msg = ('CM-26383: Switch is running version [6.5.14-cl3u25] of '
               '[bcm-sdk] and has bridge-access configured on {}! See '
               'CM-26383 fixed in 3.7.10.'.format(ba))
        problems.append(msg)
    if len(bpv) > 0:
        msg = ('CM-26383: Switch is running version [6.5.14-cl3u25] of '
               '[bcm-sdk] and has bridge-pvid configured on {}! See CM-26383 '
               'fixed in 3.7.10.'
               .format(bpv))
        problems.append(msg)
    # All done!
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_core_files(deprecated, satisfied, CL, info):
    """Detect the presence of core files."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, info)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, info)
    directory = CL + '/core'
    if not os.path.isdir(directory):
        logger.debug('Directory [{}] was not found.'.format(directory))
        satisfied.append(name)
        return(satisfied, info)
    cores = os.listdir(directory)
    if len(cores) > 0:
        msg = ('CORE-FILE-FOUND: Found the following core file(s): {} !'
               .format(cores))
        logger.debug(msg)
        info.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, info)


def detect_dhcrelay_probs(deprecated, satisfied, interfaces, services, # noqa
                          problems, v4_routes):
    """Detect problems with dhcrelay configurations."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_dhcrelay_conf', 'discover_ifquery', 'discover_v4_routes']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    # Walk through each dhcrelay instance that is configured:
    if 'dhcrelay' not in services:
        logger.debug('No dhcrelay instances configured.')
        return(satisfied, problems)
    for vrf in services['dhcrelay']['config']['vrf']:
        logger.debug('Analyzing dhcrelay instance for VRF [{}].'
                     .format(vrf))
        gtg = True
        # We can't do detections without all of the info we use to do them!
        required = ['servers', 'interfaces']
        for field in required:
            if field not in services['dhcrelay']['config']['vrf'][vrf]:
                logger.debug(
                    'Field [{}] not found in config for dhcrelay in '
                    'VRF [{}].'.format(field, vrf))
                gtg = False
        if not gtg:
            continue
        # Look for non-existent interfaces:
        noint = []
        for iface in services['dhcrelay']['config']['vrf'][vrf]['interfaces']:
            if iface not in interfaces:
                noint.append(iface)
        if len(noint) > 0:
            msg = ('NONEXISTENT-INTERFACE: dhcrelay instance [{}] is '
                   'configured for non-existent interface(s) {}!'
                   .format(vrf, noint))
            logger.debug(msg)
            problems.append(msg)
        # Verify route to configured servers:
        for server in services['dhcrelay']['config']['vrf'][vrf]['servers']:
            default = False
            route_exists = False
            if vrf not in v4_routes:
                continue
            for subnet in v4_routes[vrf]:
                # If server in a subnet,
                # set found flag and continue
                if '0.0.0.0/0' in subnet:
                    default = True
                    continue
                if (ipaddress.ip_address(server) in
                   ipaddress.ip_interface(subnet).network):
                    route_exists = True
                    break
            # If no matching local subnet was found, add warning message.
            if not route_exists and not default:
                msg = ("DHCRELAY-NO-ROUTE: No route to configured server"
                       " [{}] in vrf [{}]!"
                       .format(server, vrf))
                logger.debug(msg)
                problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_dependent_ports_intersect(deprecated, satisfied, bridges, bonds, # noqa
                                     interfaces, problems):
    """
    Check to see if any physical interface is slaved to multiple interfaces.

    # Example: An interface is a member of a bond and also specified as a
    # bridge-port of a bridge, etc.  ZD 8414
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    for bridge in bridges:
        logger.debug("Analyzing bridge [{}].".format(bridge))
        # Compare the bridge-ports in this bridge with the bridge-ports in
        # all other bridges.
        if 'bridge-ports' not in interfaces[bridge]:
            continue
        for bridge2 in bridges:
            # We don't need to compare a bridge to itself.
            if 'bridge-ports' not in interfaces[bridge2]:
                continue
            if bridge != bridge2:
                logger.debug("Comparing bridge [{}] to bridge [{}]"
                             .format(bridge, bridge2))
                # Create a list of all intersecting ports for the two
                # interfaces being compared.
                intersect = list(set(interfaces[bridge]['bridge-ports']) &
                                 set(interfaces[bridge2]['bridge-ports']))
                if len(intersect) > 0:
                    msg = ("CONFIG ERROR DETECTED: bridge [{}] shares "
                           "dependent ports {} with bridge [{}]!"
                           .format(bridge, intersect, bridge2))
                    problems.append(msg)
                    logger.debug(msg)
        # Compare the bridge-ports in this bridge with the bond-slaves in all
        # bonds.
        for bond in bonds:
            if 'bond-slaves' not in interfaces[bond]:
                continue
            logger.debug("Comparing bridge [{}] to bond [{}]"
                         .format(bridge, bond))
            intersect = list(set(interfaces[bridge]['bridge-ports']) &
                             set(interfaces[bond]['bond-slaves']))
            if len(intersect) > 0:
                msg = ("CONFIG ERROR DETECTED: bridge [{}] shares dependent "
                       "ports {} with bond [{}]!".format(bridge, intersect,
                                                         bond))
                problems.append(msg)
                logger.debug(msg)
    # At this point, all bridges have been compared to all bonds.  We now need
    # to compare all bonds to all other bonds.
    for bond in bonds:
        if 'bond-slaves' not in interfaces[bond]:
            continue
        logger.debug("Analyzing bond [{}]".format(bond))
        # Compare the bond-slaves in this bond with the bond-slaves of all
        # other bonds.
        for bond2 in bonds:
            # We don't need to compare a bond to itself.
            if bond != bond2:
                if 'bond-slaves' not in interfaces[bond2]:
                    continue
                logger.debug(
                    "Comparing bond [{}] to bond [{}]".format(bond, bond2))
                intersect = list(set(interfaces[bond]['bond-slaves']) &
                                 set(interfaces[bond2]['bond-slaves']))
                if len(intersect) > 0:
                    msg = ("CONFIG ERROR DETECTED: bond [{}] shares dependent"
                           " ports {} with bond [{}]!"
                           .format(bond, intersect, bond2))
                    problems.append(msg)
                    logger.debug(msg)
    satisfied.append(name)
    return(satisfied, problems)


def detect_dup_ip_mac(deprecated, satisfied, support_path, warnings): # noqa
    """Detect duplicate IP->MAC mappings."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    filename = support_path + 'bgp.evpn.route'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return(satisfied, warnings)
    logger.debug("Parsing {}".format(filename))

    # Read bgp.evpn.route
    with open(filename) as f:
        route_str = f.read()
    f.close()

    # Set up our compiled regular expressions.
    prefix_pat = re.compile('\[2\]:\[0\]:\[0\]:\[48\]:\[' # noqa
                            '(?P<mac_addr>\S+)\]:\[\d+\]:'
                            '\[(?P<ip_addr>\S+)\]')
    nh_pat = re.compile('(?P<nh>\S+)') # noqa
    rd_pat = re.compile('Route Distinguisher: (?P<rd>\S+)') # noqa

    # Track which line in route_str we are looking at.
    next = 0

    # Dictionaries to hold hosts and RDs.
    hosts = {}
    hosts_rd = {}

    # Split route_str into lines - just to be safe.
    lines = route_str.splitlines()

    # Iterate through the contents of route_str
    for line in lines:
        next += 1
        # Look for a Route Distinguisher line.
        m = rd_pat.search(line)
        if m:
            rd = m.group('rd')
        m = prefix_pat.search(line)
        if not m:
            continue
        # If we have a an RD, we can look for IPs, MACs and BGP NHs.
        ip_addr = m.group('ip_addr')
        mac_addr = m.group('mac_addr')
        next_line = lines[next]
        m = nh_pat.search(next_line)
        nh = m.group('nh')
        # If we haven't seen this IP before, create a list for it in dict hosts
        # and also add a dict for it in dict hosts_rd.
        if ip_addr not in hosts:
            hosts[ip_addr] = []
            hosts_rd[ip_addr] = {}
        path = (mac_addr, nh)
        # If we don't have this path in hosts, we need to add it.
        if path not in hosts[ip_addr]:
            hosts[ip_addr].append(path)
        # If we don't have this path in hosts_rd, we need to add it.
        if not hosts_rd[ip_addr].get(path):
            hosts_rd[ip_addr][path] = []
        # If this RD is not in hosts_rd, we need to add it.
        if rd not in hosts_rd[ip_addr][path]:
            hosts_rd[ip_addr][path].append(rd)

    # Heavy lifting is now done.  Iterate through the data we have and look for
    # any hosts with more than one entry and add them to our list of problems.
    if len(hosts) > 1:
        for item in hosts:
            if len(hosts[item]) > 1:
                for macs in hosts[item]:
                    msg = ('DUPE-IP-TO-MAC: {} => {} via {}, RDs: {}'
                           .format(item, macs[0], macs[1],
                                   hosts_rd[item][macs]))
                    warnings.append(msg)

    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_egp_to_igp(deprecated, satisfied, features, warnings):
    """Detect and warn about redistribution of EGP into IGP."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_frr_ospf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # List of EGP protocols.
    egps = ['bgp']
    # List of IGP protocols that shouldn't have EGPs redistributed into them.
    igps = ['ospf-v2', 'ospf-v3']
    # Iterate through IGPs and look for redistribution of EGPs into them.
    for igp in igps:
        if igp in features:
            for vrf in features[igp]:
                logger.debug("Analyzing at {} in VRF {}".format(igp, vrf))
                if 'redistribute' in features[igp][vrf]:
                    for egp in egps:
                        if egp in features[igp][vrf]['redistribute']:
                            msg = ('EGP-TO-IGP-REDISTRIBUTION: [{}] is being '
                                   'redistributed into [{}] in [{}] instance!'
                                   .format(egp, igp, vrf))
                            logger.debug(msg)
                            warnings.append(msg)
    satisfied.append(name)
    return(satisfied, warnings)


def detect_failed_services(deprecated, features, satisfied, # noqa
                           problems, services):
    """Detect when a configured service is in a failed state.

    # If we discovered failed services in discover_services, we need to add
    # them to list problems[]
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_ifquery', 'discover_services']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)

    # Ignore these since they show up because of the file format.
    ignore = ['clagd', 'dhcpd', 'dhcpd6', 'dhcrelay', 'dhcrelay6', 'frr',
              'ledmgrd', 'lldpd', 'netd', 'netq-agent', 'netqd', 'ntp',
              'portwd', 'ptmd', 'pwmpd', 'rdnbrd', 'snmpd', 'snmptrapd',
              'sshd', 'switchd', 'sx_sdk', 'vxsnd', 'vxrd']

    if 'FAILED-SERVICES' in services:
        for item in services['FAILED-SERVICES']:
            msg = ("FAILED SERVICE: Service [{}] is in FAILED state!"
                   .format(item))
            problems.append(msg)
            logger.debug(msg)
    # If a service is configured in a VRF that doesn't exist, its a problem!
    for service in services:
        if 'FAILED-SERVICES' in service or 'VRFs' not in features:
            continue
        for vrf in services[service]['vrf']:
            if 'default' in vrf:
                continue
            if 'VRFs' not in features and vrf not in ignore:
                msg = ('CONFIG-ERROR: Service [{}] configured in non-existent'
                       ' VRF [{}]!'.format(service, vrf))
                logger.debug(msg)
                problems.append(msg)
                continue
            if vrf not in features['VRFs'] and vrf not in ignore:
                msg = ('CONFIG-ERROR: Service [{}] configured in non-existent'
                       ' VRF [{}]!'.format(service, vrf))
                logger.debug(msg)
                problems.append(msg)
    satisfied.append(name)
    return(satisfied, problems)


def detect_forwarding_disabled(deprecated, satisfied, features, forwarding, # noqa
                               interfaces, warnings):
    """
    Detect when forwarding is disabled.

    # Warn if ip-forwarding or ip6-forwarding is disabled on an interface,
    # in FRR or via sysctl.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, forwarding, warnings)
    reqs = ['discover_ifquery', 'discover_sysctl', 'discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, forwarding, warnings)
    disabled = []
    disabled6 = []
    for iface in interfaces:
        if ('ip-forward' in interfaces[iface] and 'address' in
                interfaces[iface]):
            disabled.append(iface)
        if ('ip6-forward' in interfaces[iface] and 'address' in
                interfaces[iface]):
            disabled6.append(iface)
    if len(disabled) > 0:
        if 'interfaces' not in forwarding:
            forwarding['interfaces'] = {}
        forwarding['interfaces']['ip forwarding disabled'] = disabled
        msg = ("IP-FORWARDING-DISABLED: ip-forwarding is disabled on "
               "interface(s) {} !".format(disabled))
        warnings.append(msg)
        logger.debug(msg)
    if len(disabled6) > 0:
        if 'interfaces' not in forwarding:
            forwarding['interfaces'] = {}
        forwarding['interfaces']['ipv6 forwarding disabled'] = disabled6
        msg = ("IP6-FORWARDING-DISABLED: ip6-forwarding is disabled on "
               "interface(s) {} !".format(disabled6))
        warnings.append(msg)
        logger.debug(msg)
    if 'FRR' in forwarding:
        if 'ip forwarding' in forwarding['FRR']:
            msg = ("IP-FORWARDING-DISABLED: ip forwarding is disabled in FRR!")
            warnings.append(msg)
            logger.debug(msg)
        if 'ipv6 forwarding' in forwarding['FRR']:
            msg = ("IP6-FORWARDING-DISABLED: ipv6 forwarding is disabled in "
                   "FRR!")
            warnings.append(msg)
            logger.debug(msg)
    if 'sysctl' in forwarding:
        if 'net.ipv4.conf.all.forwarding' in forwarding['sysctl']:
            msg = ("IP-FORWARDING-DISABLED: ip forwarding is disabled in "
                   "sysctl!")
            warnings.append(msg)
            logger.debug(msg)
        if 'net.ipv6.conf.all.forwarding' in forwarding['sysctl']:
            msg = ("IP6-FORWARDING-DISABLED: ipv6 forwarding is disabled in "
                   "sysctl!")
            warnings.append(msg)
            logger.debug(msg)
    satisfied.append(name)
    return(satisfied, forwarding, warnings)


def detect_frr_ip_config(deprecated, satisfied, features, warnings):
    """
    Detect IP config in FRR.

    # Warn if we have discovered IP/IPv6 address configuration in FRR
    # since this could cause problems for customers during upgrades, etc.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Look for interfaces with IPv4 addresses configured in FRR.
    if 'FRR v4 addresses' in features:
        for iface in features['FRR v4 addresses']:
            msg = ('IP-CONFIG-IN-FRR: Interface [{}] has IPv4 config for {}!'
                   .format(iface, features['FRR v4 addresses'][iface]))
            logger.debug(msg)
            warnings.append(msg)
    # Look for interfaces with IPv6 addresses configured in FRR.
    if 'FRR v6 addresses' in features:
        for iface in features['FRR v6 addresses']:
            msg = ('IP6-CONFIG-IN-FRR: Interface [{}] has IPv6 config for {}!'
                   .format(iface, features['FRR v6 addresses'][iface]))
            logger.debug(msg)
            warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_high_discards(deprecated, satisfied, high_discards, interfaces, # noqa
                         warnings):
    """
    Calculate the % Drops on each interface and warn if they're too high.

    This is indicative of a possible problem with the interface.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("Detection [{}] is deprecated. Skipping".format(name))
        return(satisfied, high_discards, warnings)
    reqs = ['discover_ethtool_stats']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, high_discards, warnings)
    # Specify the minumum number of "Total_Pkts_[In|Out]" on an interface
    # before we will analyze its discard rate.
    min_packets = 10000
    # Speficy the discard rate (% of total packets) at which we are concerned.
    max_discard_rate = float(3.0)
    # Spefify the discard rate which we consider to be indicative of a counter
    # roll which will cause false warning.
    suspect_discard_rate = float(95.0)
    # Speficy the fields that we sum to get total packets.
    pkts = ['HwIfInUcastPkts', 'HwIfInBcastPkts', 'HwIfInMcastPkts',
            'HwIfOutUcastPkts', 'HwIfOutMcastPkts', 'HwIfOutBcastPkts', ]
    # Speficy the discard fields.
    discards = ['HwIfInDiscards', 'HwIfOutDiscards']
    # All of the fields!
    fields = pkts + discards
    # Iterate through the interfaces
    for iface in interfaces:
        total_pkts_in = 0
        total_pkts_out = 0
        skip = False
        logger.debug("Analyzing {}".format(iface))
        for field in fields:
            # If we're missing a field for an interface, we don't have good
            # data.  Easier to just skip it!
            if field not in interfaces[iface]:
                logger.debug("Did not find {} for {}!".format(field, iface))
                skip = True
        if skip:
            continue
        # Sum up all of the In and Out Pkts fields to get Total_Pkts_
        for pkt_ctr in pkts:
            if "In" in str(pkt_ctr):
                total_pkts_in += int(interfaces[iface][pkt_ctr])
            if "Out" in pkt_ctr:
                total_pkts_out += int(interfaces[iface][pkt_ctr])
        interfaces[iface]['Total_Pkts_In'] = total_pkts_in
        interfaces[iface]['Total_Pkts_Out'] = total_pkts_out
        logger.debug('Total_In = {}'.format(total_pkts_in))
        logger.debug('Total_Out = {}'.format(total_pkts_out))

        # Calculate the discard percentage.
        for discard in discards:
            # We can't divide by 0 so, if the discards is 0, no need to calc!
            if interfaces[iface][discard] > 0:
                # (discards / total) * 100 = % of discards
                if ("In" in discard and interfaces[iface]['Total_Pkts_In'] >
                        min_packets):
                    in_disc_pct = (
                        (float(interfaces[iface][discard]) /
                         float(interfaces[iface]['Total_Pkts_In'])) * 100)
                    interfaces[iface]['In_Pct_Discards'] = float(in_disc_pct)
                    if in_disc_pct >= max_discard_rate:
                        if in_disc_pct < suspect_discard_rate:
                            msg = ("HIGH DISCARD RATE: Interface [{}] Input "
                                   "Discard rate [{}] is >= {} percent !"
                                   .format(iface, round(in_disc_pct, 2),
                                           max_discard_rate))
                            warnings.append(msg)
                            logger.debug(msg)
                            high_discards[iface] = interfaces[iface]
                if ("Out" in discard and
                        interfaces[iface]['Total_Pkts_Out'] > min_packets):

                    out_disc_pct = (
                        (float(interfaces[iface][discard]) /
                         float(interfaces[iface]['Total_Pkts_Out'])) * 100)
                    interfaces[iface]['Out_Pct_Discards'] = float(out_disc_pct)
                    if out_disc_pct >= max_discard_rate:
                        if out_disc_pct < suspect_discard_rate:
                            msg = ("HIGH DISCARD RATE: Interface [{}] Output "
                                   "Discard rate [{}] is >= {} percent !"
                                   .format(iface, round(out_disc_pct, 2),
                                           max_discard_rate))
                            warnings.append(msg)
                            logger.debug(msg)
                            high_discards[iface] = interfaces[iface]
    satisfied.append(name)
    return(satisfied, high_discards, warnings)


def detect_hsflow_unsupported(deprecated, satisfied, discovered, problems,
                              services):
    """Detect hsflowd configured on AS4610."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_platform', 'discover_services']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)

    if 'hsflowd' in services and '4610' in discovered['platform.detect']:
        msg = ('UNSUPPORTED-CONFIG: hsflowd is enabled on an AS4610. '
               'This is an unsupported configuration.')
        problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_link_flaps(deprecated, satisfied, CL, interfaces, warnings):
    """Detect ?excessive? link flaps."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_zebra_intf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Iterate through our list of interfaces and look for ?excessive? link
    # flaps.
    excessive = 10
    flapped = []
    for iface in interfaces:
        transitions = 0
        if 'link ups' in interfaces[iface]:
            transitions = int(interfaces[iface]['link ups'])
        if 'link downs' in interfaces[iface]:
            transitions = transitions + int(interfaces[iface]['link downs'])
        if transitions >= excessive:
            flapped.append(iface)
    if len(flapped) > 0:
        msg = ('EXCESSIVE-LINK-FLAPS: Interface(s) {} has transitioned '
               'state >= 10 times!'
               .format(flapped))
        logger.debug(msg)
        warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_link_pause(deprecated, satisfied, features, warnings):
    """Detect link_pause enabled."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_traffic_conf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Look for link_pause enabled.
    if 'link_pause' in features:
        for group in features['link_pause']:
            msg = ('LINK-PAUSE-ENABLED: Found ports {} configured in '
                   'pause_port_group [{}] of traffic.conf!'
                   .format(features['link_pause'][group], group))
            logger.debug(msg)
            warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_lnv_vxlan(deprecated, satisfied, features, services, warnings):
    """Detect when both LNV and VxLAN are configured."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Warn if both LNV and VxLAN config has been found.
    evpn = False
    if 'bgp' in features:
        for vrf in features['bgp']:
            if ('address-family' in features['bgp'][vrf] and 'l2vpn evpn' in
                    features['bgp'][vrf]['address-family']):
                evpn = True
    if 'LNV' in features and evpn:
        msg = ('CONFIG-ERROR: Switch contains mutually exclusive config for '
               'both EVPN and LNV!')
        logger.debug(msg)
        warnings.append(msg)
    # Warn is LNV services found running and VxLAN is configured.
    running = []
    if 'vxrd' in services:
        running.append('vxrd')
    if 'vxsnd' in services:
        running.append('vxsnd')

    if len(running) > 0 and evpn:
        msg = ('CONFIG-ERROR: Switch is configured for EVPN but LNV service(s'
               ') {} are running!'
               .format(running))
        logger.debug(msg)
        warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_log_sigs(deprecated, satisfied, CL, info, problems, support_path, # noqa
                    warnings):
    """
    Iterate through files looking for known signatures.

    # To add a new signature:
    # (1) Add the signature to the appropriate (infos, probs, warns) list.
    # (2) Add the appropriate hint for the signature to hints.
    # (3) Add - if necessary - the filename to files.
    # (4) Add the base directory - if necessary - to basedirs.
    #
    # To add a regular expression match, add the appropriate entry to
    # list regexps.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, info, {}, {}, problems, warnings, {})
    reqs = ['CL', 'find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, info, {}, {}, problems, warnings, {})

    # Whitelist of strings to ignore.
    whitelist = [
        '[EC 100663314]',
        '[EC 100663299]',
        '[EC 33554454]',
        '[EC 33554505]',
        '[EC 33554451]',
        '[EC 134217740]'
        ]

    # Regular Expressions: This is how we do regular expression matches.
    # This is a list of lists.  Categories are infos, warns, probs.
    # Format:
    # ['Name',
    # 'Regex with (?P<match>) enabled',
    # 'category',
    # 'hint',
    # oneshot (True/False),
    # sample logs (True, False),
    # ['logs', 'interested'],
    # [Special Log Category]]
    #
    # As shown in the 'Uncategorized FRR Error' regexp, you need to specify the
    # 'interesting' part of the match using (?P<match>REGEX).  This is the
    # portion of the match that will be reported.
    #
    # Note: regexp matches are very computationally expensive and will make
    # TE take longer to execute.  If you can achieve your goal with a string
    # match, please use a string match.
    regexps = [ # noqa
        ['Uncategorized FRR Error', # noqa
        '(\[(?P<match>EC \d+)\])',
        'warns',
        ('Ask in #routing if this EC is of concern. Feedback (toxic or '
         'whitelist) should be added to GSS-131.'),
        True,
        False,
        ['frr', 'journal'],
        True,
        ],
        ['Invoked OOM Killer',
         '((?P<match>\S+)\sinvoked oom-killer)', # noqa
        'probs',
        ('A process has invoked the OOM killer.'),
        True,
        False,
        ['dmesg', 'syslog'],
        False,
         ],
        ['OOM Killer Victim', # noqa
         '(Kill process \d+ \W(?P<match>\w+)\W)',
         'probs',
         'Process was the victim of the OOM Killer.',
         True,
         False,
         ['dmesg', 'syslog'],
         False,
         ],
        ['Out of memory', # noqa
         '(Kill process \S+ \W(?P<match>\w+)\W)',
         'probs',
         'Process mentioned by OOM Killer.',
         True,
         False,
         ['dmesg', 'syslog'],
         False,
         ],
        ['NCLU Config Commands',
        '(?P<match>net (add|del|commit|abort) .+)',
        None,
        None,
        True,
        False,
        ['netd-history'],
        False,
        ],
        ['NCLU Show Commands',
        '(?P<match>net show .+)\"',
        None,
        None,
        True,
        False,
        ['netd.log'],
        False,
        ],
        ['Cold Boot', # noqa
        '((?P<match>Boot flags: Cold boot))',
        'infos',
        ('Switch was cold-booted.'),
        True,
        False,
        ['switchd', 'systemd'],
        False,
        ],
        ['OSError', # noqa
        '((?P<match>OSError))',
        'warns',
        ('OSError Detected.'),
        True,
        True,
        ['clagd', 'sys', 'switch'],
        False,
        ],
        ['CM-24712',
        '((?P<match>:#012  File "/usr/sbin/poed", line 855))',
        'probs',
        ('Switch hit POED bug CM-24712 - Fixed in CL 3.7.7'),
        True,
        True,
        ['syslog'],
        False,
        ],
    ]

    # This is a list of signatures for informational purposes.
    infos = [
        'sysrq',
        ]

    # This is a list of signatures to look for in the file that indicate a
    # problem.
    probs = [
        'NMI watchdog: BUG: soft lockup',
        'CRIT bcm_l3_host_add failed',
        'CRIT bcm_l3_egress_ecmp_create failed',
        'CRIT bcm_l3_egress_destroy failed',
        'CRIT add_update_route: hal_route_to_hw_route',
        'CRIT bcm_l3_route_add failed',
        'CRIT Cannot add',
        '_soc_sbusdma_error_details: Error while reading descriptor fro',
        '_soc_sbusdma_desc: Abort Failed',
        'I2C read error - addr: 0x6',
        'I2C write error - addr: 0x6',
        'system ID mismatch',
        'enabled    failed',
        'blk_update_request: critical target error',
        'blk_update_request: I/O error',
        'device reported invalid CHS sector',
        'failed command: WRITE FPDMA QUEUED',
        'btrfs_dev_stat_print_on_error:',
        'BTRFS: error',
        'Skipping commit of aborted transaction',
        'BTRFS: Transaction aborted',
        'un-correctable error',
        'sxd_get_dev_list error',
        'Failed to open SX-API',
        'failed to configure the requested setup',
        'CRIT No backends found',
        'Failed accessing MCIA register through CMD IFC',
        'sxd_ioctl (CTRL_CMD_ACCESS_REG - MCIA) error',
        'ERR sfptab_entry_mcia_read module',
        'Aborting command SX_CMD_ACCESS_REG',
        "AttributeError: 'NoneType' object has no attribute 'replace'",
        "does not match four-port grouping",
        "Error in `/usr/sbin/switchd': free(): invalid next size (fast)",
        "NMI: IOCK error (debug interrupt?) for reason",
        "i801_smbus 0000:00:1f.3: SMBus is busy, can't use it!",
        " malloc",
        ]

    # This is a list of signatures to look for in the file that indicate a
    # warning.
    warns = [
        'VxLAN feature not supported',
        'WARN Detected excessive moves',
        'SLOW THREAD:',
        'bgpd state -> unresponsive',
        'I2C subsystem initialization failed',
        'start request repeated too quickly, refusing to start',
        'scsi host6: usb-storage',
        'idVendor=13fe, idProduct=5200',
        'usb 1-1.4: Product: USB DISK 2.0',
        'eUSB',
        'early-access',
        ]

    # This is a list of Hints for string matches.
    # Any info, warn or prob string MUST have an associated
    # Hint!
    hints = {}
    hints['NMI watchdog: BUG: soft lockup'] = 'See ZD 8707'
    hints['CRIT bcm_l3_host_add failed'] = 'See ZD 8531'
    hints['CRIT bcm_l3_egress_ecmp_create failed'] = 'See ZD 8531'
    hints['CRIT bcm_l3_egress_destroy failed'] = 'See ZD 8531'
    hints['CRIT add_update_route: hal_route_to_hw_route'] = 'See ZD 8531'
    hints['CRIT bcm_l3_route_add failed'] = 'See ZD 8531'
    hints['CRIT Cannot add'] = 'See ZD 8531'
    hints['_soc_sbusdma_error_details: Error while reading descriptor fro'] = (
        'See CM-9608')
    hints['_soc_sbusdma_desc: Abort Failed'] = 'See CM-9608'
    hints['I2C read error - addr: 0x6'] = 'Possible CM-21581'
    hints['I2C write error - addr: 0x6'] = 'Possible CM-21581'
    hints['VxLAN feature not supported'] = 'See ZD 7188'
    hints['WARN Detected excessive moves'] = 'See ZD 8193'
    hints['SLOW THREAD:'] = 'See ZD 8629'
    hints['bgpd state -> unresponsive'] = 'See ZD 8629'
    hints['Boot flags: Cold boot'] = 'Switch was cold-booted. (power-cycle)'
    hints['I2C subsystem initialization failed'] = 'See ZD 8712'
    hints['start request repeated too quickly, refusing to start'] = (
        'See ZD 8712')
    hints['scsi host6: usb-storage'] = 'See CM-19933'
    hints['idVendor=13fe, idProduct=5200'] = 'E-USB DISK DETECTED See CM-19933'
    hints['usb 1-1.4: Product: USB DISK 2.0'] = 'See CM-19933'
    hints['eUSB'] = 'See CM-19933'
    hints['system ID mismatch'] = 'See ZD 8696'
    hints['enabled    failed'] = 'Failed Service'
    hints['blk_update_request: critical target error'] = 'See ZD 8524,CM-19933'
    hints['blk_update_request: I/O error'] = 'See ZD 8524,CM-19933'
    hints['device reported invalid CHS sector'] = 'See ZD 8524,CM-19933'
    hints['failed command: WRITE FPDMA QUEUED'] = 'See ZD 8524,CM-19933'
    hints['btrfs_dev_stat_print_on_error:'] = 'See ZD 8524,CM-19933'
    hints['BTRFS: error'] = 'See ZD 8524,CM-19933'
    hints['Skipping commit of aborted transaction'] = 'See ZD 8524,CM-19933'
    hints['BTRFS: Transaction aborted'] = 'See ZD 8524,CM-19933'
    hints['early-access'] = 'Early Access REPO enabled!'
    hints['un-correctable error'] = 'PARITY ERROR! See ZD 6825'
    hints['Failed to open SX-API'] = 'See ZD 8858'
    hints['failed to configure the requested setup'] = 'See ZD 8858'
    hints['CRIT No backends found'] = 'See ZD 8858'
    hints['un-correctable error'] = 'See ZD 8858'
    hints['sxd_get_dev_list error'] = 'See ZD 8858'
    hints['Failed accessing MCIA register through CMD IFC'] = (
        'Please cold-boot switch to remediate.')
    hints['sxd_ioctl (CTRL_CMD_ACCESS_REG - MCIA) error'] = (
        'Please cold-boot switch to remediate.')
    hints['ERR sfptab_entry_mcia_read module'] = (
        'Please cold-boot switch to remediate.')
    hints['Aborting command SX_CMD_ACCESS_REG'] = (
        'Please cold-boot switch to remediate.')
    hints["AttributeError: 'NoneType' object has no attribute 'replace'"] = (
        'See ZD 9179 / CM-23131')
    hints["does not match four-port grouping"] = (
            'INVALID ports.conf config - Mixed Sisters ERROR on Falcon or '
            'Eagle core switch!')
    hints["Error in `/usr/sbin/switchd': free(): invalid next size (fast)"] = (
            'Switchd core - See: CM-24508')
    hints["NMI: IOCK error (debug interrupt?) for reason"] = (
            'See: ZD 10856')
    hints["i801_smbus 0000:00:1f.3: SMBus is busy, can't use it!"] = (
            'See CM-23390')
    hints[" malloc"] = ('memory access error detected')
    hints['sysrq'] = ('SysRq received. Noisy Console Connection???')

    # Define the base directory to locate log various log files.  Remember the
    # trailing '/'...
    basedirs = {}
    basedirs['FRR'] = CL + '/var/log/frr/'
    basedirs['SUPPORT'] = support_path
    basedirs['APT'] = CL + '/etc/apt/'
    basedirs['VARLOG'] = CL + '/var/log/'

    # This is a list of files to look for the signatures listed in infos, probs
    # and warns.  Format is BASE:filename with BASE referring to the basedirs
    # name listed above in dict base.  The match is 'filename*' and we will
    # read gzip files as well.
    files = ['APT:sources.list',
             'FRR:frr.log',
             'SUPPORT:systemd.journal',
             'SUPPORT:cl-service-summary',
             'SUPPORT:dmesg',
             'VARLOG:crit.log',
             'VARLOG:clagd.log',
             'VARLOG:netd-history.log',
             'VARLOG:netd.log',
             'VARLOG:switchd.log',
             'VARLOG:syslog',
             ]

    # A dict of categories and the corresponding dict to add messages for them.
    cats = {}
    cats['infos'] = 'info'
    cats['probs'] = 'problems'
    cats['warns'] = 'warnings'

    # A dict to hold log entries associated with problems or warnings.
    logs = {}

    # A dict to hold all matches for our regex matching.
    matches = {}

    # A list of any whitelisted items we have seen and ignored.
    whitelisted = []

    # Time to iterate through the files.
    for shortname in files:
        base, alias = shortname.split(':')
        filename = basedirs[base] + alias
        filelist = glob.glob(filename + '*')
        if len(filelist) < 1:
            continue
        for filename1 in filelist:
            logger.debug("Log file path is {}".format(filename1))
            # We're going to deviate slightly from the norm here and not fail
            # if we can't open a file.  It might not exist since we have a list
            # of them.
            if not os.path.isfile(filename1):
                logger.debug("Could not open {}".format(filename1))
                continue
            shortfilename1 = filename1.split('/')[-1]
            logger.debug("Reading in {}".format(shortfilename1))
            contents = []
            if '.gz' in filename1:
                try:
                    with gzip.open(filename1, 'rt') as f:
                        for line in f:
                            contents.append(line)
                    f.close()
                except: # noqa
                    continue
            else:
                try:
                    with open(filename1, encoding='ISO-8859-1') as f:
                        for line in f:
                            contents.append(line)
                    f.close()
                except: # noqa
                    continue

            # If we made it this far, we have data to parse!
            logger.debug("Parsing contents of {}".format(filename1))

            # We need to store the fact that we found a problem or warning or
            # info match.
            # This is on a per-filename basis since we want indicate which file
            # we found the signature in.
            found = {}
            # Initialize the found dict since we start over for each file.
            for cat in cats:
                found[cat] = []

            # We also need a dict to store regexp matches - per file.
            rmatches = {}

            # Time to iterate through the file and collect the data.
            for line in contents:
                # We use the stringmatch bool to save time.  If we have an
                # exact string match, we won't look for regex matches on this
                # log line.
                stringmatch = False

                # We strip the log line so it prints nicely in the TE2 report.
                stripped = line.strip()

                # Ignore commented out lines in files we parse and continue to
                # the next log line.
                if stripped.startswith('#'):
                    continue

                # We don't want jacked up log lines from this script-exporter
                # crap that has been found in some logs.
                if 'script-exporter' in stripped:
                    continue

                # Look and see if we have a whitelist match.  If so,
                # No need to look for anything else on this log line.
                ignored = False
                for ignore in whitelist:
                    if ignore in stripped:
                        ignored = True
                        logger.debug('Ignoring whitelisted "{}" found in {}.'
                                     .format(ignore, shortfilename1))
                        if ignore not in whitelisted:
                            whitelisted.append(ignore)
                            logger.debug(whitelisted)
                            if 'whitelisted' not in logs:
                                logs['whitelisted'] = []
                            if stripped not in logs['whitelisted']:
                                logs['whitelisted'].append(
                                    '{}: {}'.format(shortfilename1,
                                                    stripped))
                if ignored:
                    logger.debug('Not looking at line further because of'
                                 ' whitelist match.')
                    continue

                # Iterate through our categories (probs, warns, infos) and look
                # for string matches.
                for cat in cats:
                    # Iterate through the signatures for this category.  Ignore
                    # special categories like NCLU.
                    if cat not in locals():
                        continue
                    for item in locals()[cat]:
                        # Does that string signature appear in this line?
                        if item in stripped:
                            stringmatch = True
                            logger.debug('Found {}'.format(item))
                            # Have we already seen this signature in this file?
                            if item not in found[cat]:
                                # If not, add it to our found signatures.
                                found[cat].append(item)
                                # If we haven't seen this log sample before,
                                # Add it to the the appropriate category list
                                # in our logs dict. But we first need to
                                # make sure that the list exists!
                                if cats[cat] not in logs:
                                    logs[cats[cat]] = []
                                if stripped not in logs[cats[cat]]:
                                    logs[cats[cat]].append('{}: {}'
                                                           .format(
                                                                shortfilename1,
                                                                stripped))

                # If we haven't found a stringmatch, we now look for a regular
                # expression match.  This is more computationally expensive so,
                # we only do it if we don't have a string match already.
                # This is about the 10th iteration of this particular code that
                # I've written to try to achieve the level of information we
                # want for regular expression matches.  It may not be perfect
                # but it is better than not having regex matching as it scales
                # much better.  Its cheaper to do one regex match than to do
                # a bunch of string matches.
                if not stringmatch:
                    for i in regexps: # noqa
                        # Are we interested in running this match agsinst this
                        # logfile?  If not, don't waste the time doing it!
                        skip = True
                        for interested in i[6]:
                            if interested in shortfilename1:
                                skip = False
                        if skip:
                            continue
                        # Search for our regexp in the log line.
                        m = re.search(i[1], stripped)
                        # Did we get a regex match on the log line?
                        if m:
                            # If we have a match, we want to know all of
                            # the matched strings for a regex for a
                            # cl-support file.
                            if i[0] not in matches:
                                matches[i[0]] = []
                            if m.group('match') not in matches[i[0]]:
                                matches[i[0]].append(m.group('match'))
                            else:
                                # If this is a one-shot, we only take
                                # one sample per match, per cl-support.
                                if i[4]:
                                    continue
                            # If we have a match, we need to store the
                            # match info in the appropriate category of
                            # the rmatches dict but we need to make sure
                            # the category exists first.
                            if i[2] not in rmatches:
                                rmatches[i[2]] = {}
                            # Add the REGEX name to the dictself.
                            if i[0] not in rmatches[i[2]]:
                                rmatches[i[2]][i[0]] = {}
                            # Add the actual matched string to the dict.
                            if m.group('match') not in rmatches[i[2]][i[0]]:
                                rmatches[i[2]][i[0]][m.group('match')] = i[3]
                                # Is log sampling enabled?
                                if not i[5]:
                                    if not i[7]:
                                        continue
                                # Is this a special log category?
                                if i[7]:
                                    logcat = i[0]
                                else:
                                    logcat = cats[i[2]]
                                # We need to add this log sample to the
                                # appropriate logs category but we need to
                                # make sure that the category exists in
                                # dict logs first.
                                if logcat not in logs:
                                    logs[logcat] = []
                                # We are only going to add the log sample
                                # one time - even if it has multiple regexp
                                # matches.
                                if stripped not in logs[logcat]:
                                    logs[logcat].append(
                                            '{}: {}'.format(shortfilename1,
                                                            stripped))
                # We have parsed the last line in the file at this point.

            # Generate our messages for string signatures that were found.
            for cat in cats:
                # Did we find any signatures for this category?
                if len(found[cat]) > 0:
                    # If we did, we need notify of that detected signature.
                    for item in found[cat]:
                        msg = ('SIGNATURE: [ {} ] found in [ {} ]! {}'
                               .format(item, shortfilename1, hints[item]))
                        logger.debug(msg)
                        locals()[cats[cat]].append(msg)

            # Generate our TE2 messages for any regex matches we had in this
            # log file.
            for i in rmatches:
                for z in rmatches[i]:
                    list = []
                    for zz in rmatches[i][z]:
                        list.append(zz)
                    msg = ('REGEX: [{}] matches {} found in {}. {}'
                           .format(z, list, shortfilename1,
                                   rmatches[i][z][zz]))
                    if i not in locals():
                        continue
                    locals()[cats[i]].append(msg)

    # That's all folks!
    satisfied.append(name)
    return(satisfied, info, logs, matches, problems, warnings, whitelisted)


def detect_toomany_vlans(deprecated, satisfied, discovered, problems,
                         vlans_inuse):
    """Detect > 2000 VLANs configured on Spectrum ASIC."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_ifquery', 'discover_platform_detail']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if 'chipset' not in discovered:
        logger.debug('Unknown chipset - skipping.')
        return(satisfied, problems)
    if 'Spectrum' not in discovered['chipset']:
        logger.debug('Check only relevant for Spectrum - Skipping.')
        return(satisfied, problems)
    # Detection code goes here...
    if len(vlans_inuse) > 2000:
        msg = ('TOO-MANY-VLANS: {} VLANs configured. Supported max is 2000 '
               'VLANs on Spectrum ASIC!'.format(len(vlans_inuse)))
        problems.append(msg)

    # Any failure should return(satisfied) [and any other structures as
    # necessary].
    #
    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_missing_prefix_lists(deprecated, satisfied, discovered, problems): # noqa
    """Detect missing prefix-lists or matches against wrong AF prefix-lists."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if 'referenced prefix-lists' not in discovered:
        logger.debug('No prefix-lists referenced.')
        return(satisfied, problems)
    # Look for misconfigs.
    if 'bgp' in discovered['referenced prefix-lists']:
        logger.debug('Checking prefix-lists referenced in BGP config...')
        for referenced in discovered['referenced prefix-lists']['bgp']:
            found = False
            logger.debug(
                'Looking for [{}] in prefix-lists...'.format(referenced))
            if 'prefix-lists' in discovered:
                for af in discovered['prefix-lists']:
                    if referenced in discovered['prefix-lists'][af]:
                        logger.debug('Found [{}] as configured {} prefix-list'
                                     .format(referenced, af))
                        found = True
            if not found:
                msg = ('CONFIG-ERROR: Non-existent prefix-list [{}] is '
                       'referenced in BGP config!'.format(referenced))
                logger.debug(msg)
                problems.append(msg)
    if 'route-map' in discovered['referenced prefix-lists']:
        for af in discovered['referenced prefix-lists']['route-map']:
            logger.debug('Checking {} prefix-lists referenced in route-maps...'
                         .format(af))
            if 'prefix-lists' in discovered:
                for referenced in (discovered['referenced prefix-lists']
                                             ['route-map'][af]):
                    logger.debug('Looking for [{}] in {} prefix-lists...'
                                 .format(referenced, af))
                    foundwrong = False
                    if referenced in discovered['prefix-lists'][af]:
                        logger.debug('Found [{}] in {} prefix-lists...'
                                     .format(referenced, af))
                        continue
                    else:
                        for af2 in discovered['prefix-lists']:
                            if referenced in (discovered['prefix-lists']
                                                        [af2]):
                                foundwrong = True
                                wrongaf = af2
                    if foundwrong:
                        msg = ('CONFIG-ERROR: Route-map matches non-'
                               'existent *{}* prefix-list [{}]. [{}] is an'
                               ' *{}* prefix-list!'
                               .format(af, referenced, referenced, wrongaf)
                               )
                        logger.debug(msg)
                        problems.append(msg)
                    else:
                        msg = ('CONFIG-ERROR: Route-map matches '
                               'non-existent {} prefix-list [{}]!'
                               .format(af, referenced))
                        logger.debug(msg)
                        problems.append(msg)

    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_missing_route_maps(deprecated, satisfied, discovered, problems):
    """Detect referenced route-maps that are not configured."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    # Look for non-existent but referenced route-maps:
    if 'referenced route-maps' not in discovered:
        logger.debug('No referenced route-maps detected.')
        return(satisfied, problems)
    for referenced in discovered['referenced route-maps']:
        found = False
        logger.debug('Checking for existence of {}'.format(referenced))
        if 'route-maps' in discovered:
            if referenced in discovered['route-maps']:
                found = True
        if not found:
            msg = ('CONFIG-ERROR: Non-existent route-map [{}] is referenced in'
                   ' BGP config for neighbor or redistribution!'
                   .format(referenced))
            logger.debug(msg)
            problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_mlx_smbios_error(deprecated, satisfied, support_path, discovered, # noqa
                            problems):
    """Detect Mellanox SN2100 SMBIOS Error."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, discovered, problems)
    reqs = ['discover_etc', 'discover_syseeprom']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, discovered, problems)
    if 'switch-architecture' not in discovered:
        logger.debug("Unknown switch architecture.  Can not test.")
        return(satisfied, discovered, problems)
    if 'mlx' not in discovered['switch-architecture']:
        logger.debug("Switch not detected as MLX")
        return(satisfied, discovered, problems)

    if 'Product Name' not in discovered:
        logger.debug("Product name hasn't been discovered.  Can't continue!")
        return(satisfied, discovered, problems)

    ds_pn = discovered['Product Name']

    # If we were able to get ds_pn, build a list of all of the 'Product Name'
    # fields found in dmidecode.
    if 'ds_pn' in locals() and '2100' in ds_pn:
        detected = False
        filename = support_path + 'dmidecode'
        if os.path.isfile(filename):
            logger.debug("Parsing {}".format(filename))
            dmi_pn = []
            with open(filename, encoding='ISO-8859-1') as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith('Product Name'):
                        dmi_pn.append(stripped.split(":")[1].strip())
            fh.close()
        else:
            logger.debug("ERROR: Could not open {}.".format(filename))
            return(satisfied, discovered, problems)
        # If we were able to detect dmi_pn, iterate through the list and
        # look for ds_pn.  If we find it, set bool detected to True.
        if len(dmi_pn) > 0:
            for item in dmi_pn:
                if ds_pn in item:
                    detected = True
        # If we didn't find ds_pn in dmi_pn, that's a bad thing! We probably
        # found a problem and should likely report it.  We give the entire
        # list of part numbers found in dmidecode because a human may override
        # the programatic detection of the bug.
        if not detected:
            msg = ("WARNING: Mellanox SN2100 SMBIOS Error "
                   "Detected!  See GSS-110 for details.")
            problems.append(msg)
            logger.debug(msg)
            msg = ("WARNING: Product Name field in decode-syseeprom [{}] "
                   "does not match any Product Name field [{}] in "
                   "dmidecode."
                   .format(ds_pn, dmi_pn))
            logger.debug(msg)
            problems.append(msg)
    satisfied.append(name)
    return(satisfied, discovered, problems)


def detect_nondeterministic_routerid(deprecated, satisfied, features, # noqa
                                     warnings):
    """
    Detect when no router-id is explicitly configured.

    # Detect BGP or OSPFv2/v3 instances with no instance specific router-id
    # configured when there is no global router-id configured.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_frr_bgp_ip', 'discover_frr_ospf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Detect no global && no bgp router-id:
    if 'bgp' in features and 'global router-id' not in features:
        for vrf in features['bgp']:
            if 'router-id' not in features['bgp'][vrf]:
                msg = ('NONDETERMINISTIC-ROUTER-ID: BGP [{}] is configured but'
                       ' no global or instance specific router-id is '
                       'configured!'
                       .format(vrf))
                logger.debug(msg)
                warnings.append(msg)
    # Detect OSPF-v2 and no global router-id:
    if 'ospf-v2' in features and 'global router-id' not in features:
        for vrf in features['ospf-v2']:
            if 'router-id' not in features['ospf-v2'][vrf]:
                msg = ('NONDETERMINISTIC-ROUTER-ID: OSPFv2 [{}] is configured '
                       'but no global or instance specific router-id is '
                       'configured!'.format(vrf))
                logger.debug(msg)
                warnings.append(msg)
    # Detect OSPF-v3 and no global router-id:
    if 'ospf-v3' in features and 'global router-id' not in features:
        for vrf in features['ospf-v3']:
            if 'router-id' not in features['ospf-v3'][vrf]:
                msg = ('NONDETERMINISTIC-ROUTER-ID: OSPFv3 [{}] is configured '
                       'but no global or instance specific router-id is '
                       'configured!'.format(vrf))
                logger.debug(msg)
                warnings.append(msg)
    satisfied.append(name)
    return(satisfied, warnings)


def detect_ospf_unnumbered_misconfig(deprecated, satisfied, features,
                                     interfaces, problems):
    """Detect misconfigurations related to OSPF Unnumbered."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_ifquery', 'discover_ospf_interface']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if 'ospf-v2' not in features or 'ospf unnumbered' not in features:
        logger.debug('OSPF Unnumbered is not configured.')
    else:
        if 'lo' not in interfaces:
            msg = ("CONFIG ERROR DETECTED: OSPF Unnumbered configured but, no "
                   "/32 configured on interface [lo]!")
            logger.debug(msg)
            problems.append(msg)
        else:
            if 'lo' not in interfaces or 'address' not in interfaces['lo']:
                msg = ("CONFIG ERROR DETECTED: OSPF Unnumbered configured - "
                       "no /32 configured on interface [lo]! ZD 8361")
                logger.debug(msg)
                problems.append(msg)
                satisfied.append(name)
                return(satisfied, problems)
            else:
                if '/32' not in interfaces['lo']['address']:
                    msg = ("CONFIG ERROR DETECTED: OSPF Unnumbered configured"
                           " - no /32 configured on interface [lo]! ZD 8361")
                    logger.debug(msg)
                    problems.append(msg)
            for iface in features['ospf unnumbered']:
                if (iface not in interfaces or 'address' not in
                        interfaces[iface]):
                    continue
                if iface in interfaces and (interfaces[iface]['address'] !=
                                            interfaces['lo']['address']):
                    msg = ("CONFIG ERROR DETECTED: [{}] configured "
                           "for OSPF Unnumbered - address [{}] doesn't match "
                           "interface [lo] address [{}]!"
                           .format(iface, interfaces[iface]['address'],
                                   interfaces['lo']['address']))
                    logger.debug(msg)
                    problems.append(msg)
    satisfied.append(name)
    return(satisfied, problems)


def detect_ports_conf(deprecated, satisfied, discovered, problems, warnings): # noqa
    """Detect common problems in ports.conf."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems, warnings)
    reqs = ['discover_ports_conf', 'discover_platform_detail']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems, warnings)
    if 'platform' not in discovered:
        return(satisfied, problems, warnings)

#    print(discovered['platform']['ports']['capability'])
#    "capabilities": "10G, 25G, 40G, 4x10G, 50G, 100G, 2x50G, 4x25G",)
    for port in discovered['ports_conf']:
        good = False
        logger.debug('{}={}'.format(port, discovered['ports_conf'][port]))
        for setting in discovered['platform']['device']['ports']['capability']:
            if discovered['ports_conf'][port] == setting:
                logger.debug('{} matches valid setting: {}...'
                             .format(discovered['ports_conf'][port], setting))
                good = True
        if not good:
            if discovered['ports_conf'][port] == 'loopback':
                continue
            if discovered['ports_conf'][port] == 'disabled':
                continue
            if discovered['ports_conf'][port] == '1x':
                continue
            if discovered['ports_conf'][port] == '2x':
                continue
            if discovered['ports_conf'][port] == '4x':
                continue
            msg = ('INVALID-PORT-CONFIG: Port [{}] is configured as [{}]. '
                   'Should be one of: {}'
                   .format(port, discovered['ports_conf'][port],
                           discovered['platform']['device']['ports']
                           ['capability']))
            logger.debug(msg)
            problems.append(msg)

    satisfied.append(name)
    return(satisfied, problems, warnings)


def detect_redist_neigh_misconfig(deprecated, satisfied, features, interfaces, # noqa
                                  problems, services):
    """
    Detect misconfigs with redistribute neighbor.

    # Detect when customer has redistribute neighbor configured but do
    # not have a /32 configured. See ZD 8586.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_services', 'discover_ifquery', 'discover_frr_ospf',
            'discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    # There is no need to continue if the service is not enabled.
    if 'rdnbrd' not in services:
        logger.debug('Redistribute-Neighbor is not configured.')
        return(satisfied, problems)
    vrfs = ['default', 'vrf']
    redist_table = False
    # Look for redistribute table in BGP config.
    for vrf in vrfs:
        if ('bgp' in features and vrf in features['bgp'] and 'address-family'
            in features['bgp'][vrf] and 'ipv4 unicast' in
            features['bgp'][vrf]['address-family'] and 'redistribute' in
            features['bgp'][vrf]['address-family']['ipv4 unicast'] and 'table'
            in (features['bgp'][vrf]['address-family']['ipv4 unicast']
                ['redistribute'])):
            redist_table = True
            logger.debug("Found 'redistribute table' in BGP '{}'.".format(vrf))
    # Look for redistribute table in OSPF config.
    for vrf in vrfs:
        if ('ospf-v2' in features and vrf in features['ospf-v2'] and
            'redistribute' in features['ospf-v2'][vrf] and 'table' in
                features['ospf-v2'][vrf]['redistribute']):
            redist_table = True
            logger.debug("Found 'redistribute table' in OSPF-v2 '{}'."
                         .format(vrf))
    # If we haven't found the redistribute table, their config is broken.
    if not redist_table:
        msg = ("REDIST-NEIGHBOR-MISCONFIG: Service rdnbrd is configured but, "
               "no 'redistribute table' statement found in BGP or OSPF-v2 "
               "config!")
        logger.debug(msg)
        problems.append(msg)
    # Look for /32 configured on an interface other than lo.
    slash_32 = False
    for iface in interfaces:
        if ('lo' not in iface and 'address' in interfaces[iface] and '/32' in
                interfaces[iface]['address']):
            logger.debug('Found [{}] configured on [{}].'
                         .format(interfaces[iface]['address'], iface))
            slash_32 = True
    # If we haven't found a /32, redistribute neighbor is not gonna work right!
    if not slash_32:
        msg = ("REDIST-NEIGHBOR-MISCONFIG: Service rdnbrd is configured but, "
               "no /32 address configured!")
        logger.debug(msg)
        problems.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_resv_vlan_misconfigs(deprecated, satisfied, interfaces, rvr, # noqa
                                problems):
    """
    Detect reserved VLAN related misconfigs.

    # This function detects the following misconfigurations:
    # Interfaces / Bridges that have configured VLANs that intersect with RVR.
    # Reserved Vlan Range <= 300 contigious VLANs.
    # Reserved Vlan Range extends beyond 4094.
    # Reserved Vlan Range includes 4094 (possible collision with peerlink ints)
    # Reserved Vlan Range includes VLANs [0-1].
    #
    #This will need to be revisited now that reserved vlan range is changing.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_ifquery', 'discover_switchd_conf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    for iface in interfaces:
        if 'vlans' in interfaces[iface]:
            vlanset = set(interfaces[iface]['vlans'])
            collision = vlanset.intersection(range(rvr[0], rvr[1]+1))
            if 'collision' in locals() and len(collision) > 0:
                collision_list = []
                for item in collision:
                    collision_list.append(item)
                msg = ("CONFIG ERROR DETECTED: Interface [{}] is configured "
                       "for VLAN(s) {} which collides with the Reserved VLAN "
                       "Range [{} - {}]"
                       .format(iface, collision_list, rvr[0], rvr[1]))
                logger.debug(msg)
                problems.append(msg)

    # Check for RVR range that is less then 300
    rvr_size = (rvr[1] - rvr[0]) + 1
    if rvr_size < 300:
        msg = ("CONFIG ERROR DETECTED: Configured Reserved VLAN Range [{} - {}"
               "] is only {} contigious VLANs.  Range must be >= 300 VLANs!"
               .format(rvr[0], rvr[1], rvr_size))
        logger.debug(msg)
        problems.append(msg)

    # Check for RVR range that extends past VLAN 4094
    if rvr[1] > 4094:
        msg = ("CONFIG ERROR DETECTED: Configured Reserved VLAN Range [{} - {}"
               "] extends past upper limit [4094] of valid VLANs!"
               .format(rvr[0], rvr[1]))
        logger.debug(msg)
        problems.append(msg)

    # Check for RVR range includes VLAN 4094
    if rvr[1] > 4093:
        msg = ("CONFIG ERROR DETECTED: Configured Reserved VLAN Range [{} - {}"
               "] includes VLAN [4094] and may cause CLAG issues!"
               .format(rvr[0], rvr[1]))
        logger.debug(msg)
        problems.append(msg)

    # Check for RVR range that is inclusive of VLANs 0-1
    vlanset = set([0, 1])
    collision = vlanset.intersection(range(rvr[0], rvr[1]+1))
    if 'collision' in locals() and len(collision) > 0:
        collision_list = []
        for item in collision:
            collision_list.append(item)
        msg = ("CONFIG ERROR DETECTED: Configured Reserved VLAN Range [{} - {}"
               "] includes VLAN(s) {}!"
               .format(rvr[0], rvr[1], collision_list))
        logger.debug(msg)
        problems.append(msg)
    satisfied.append(name)
    return(satisfied, problems)


def detect_smonctl(deprecated, satisfied, smonctl, logs, problems): # noqa
    """Detect issues with sensors in smonctl."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, logs, problems)
    reqs = ['discover_smonctl']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, logs, problems)
    # Lets look for issues!
    for item in smonctl:
        if 'ERROR' in item:
            msg = ('SMONCTL-ERROR: {}'.format(''.join(smonctl[item])))
            logger.debug(msg)
            problems.append(msg)
        for item2 in smonctl[item]:
            if 'ABSENT' in item2:
                msg = ('SENSOR-ABSENT: {}: {}'.format(item, ''.join(item2)))
                logger.debug(msg)
                problems.append(msg)
            if 'BAD' in item2:
                msg = ('SENSOR-BAD: {}: {}'.format(item, ''.join(item2)))
                logger.debug(msg)
                problems.append(msg)
            if 'HIGH' in item2:
                msg = ('SENSOR-HIGH: {}: {}'.format(item, ''.join(item2)))
                logger.debug(msg)
                problems.append(msg)
            if 'LOW' in item2:
                msg = ('SENSOR-LOW: {}: {}'.format(item, ''.join(item2)))
                logger.debug(msg)
                problems.append(msg)
            if 'CRITICAL' in item2:
                msg = ('SENSOR-CRITICAL: {}: {}'.format(item, ''.join(item2)))
                logger.debug(msg)
                problems.append(msg)
    if 'Messages' in smonctl:
        if 'problems' not in logs:
            logs['problems'] = []
        for item in smonctl['Messages']:
            logs['problems'].append('smonctl: {}'.format(item))

    satisfied.append(name)
    return(satisfied, logs, problems)


def detect_spectre_meltdown(deprecated, satisfied, discovered, features,
                            warnings):
    """Warn if any of the spectre/meltdown mitigations are enabled."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_cmdline', 'discover_etc']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    min_version = ['3', '7', '4']
    if 'lsb-release' not in discovered:
        logger.debug("Don't have lsb-release.  Can't compare!")
        return(satisfied, warnings)
    this_version = discovered['lsb-release'].split('.')
    if this_version < min_version:
        logger.debug(
            "We don't check for Spectre/Meltdown on code prior to 3.7.4.")
        return(satisfied, warnings)
    logger.debug('Checking for Spectre/Meltdown')
    if 'Spectre/Meltdown Mitigation' in features:
        mitigations = []
        for item in features['Spectre/Meltdown Mitigation']:
            mitigations.append(item)
        msg = ('SPECTRE/MELTDOWN: Spectre/Meltdown mitigations {} are '
               'not disabled on kernel cmdline.'
               .format(mitigations))
        logger.debug(msg)
        warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_stp_discarding(deprecated, satisfied, features, warnings):
    """Warn for interfaces detected in STP Discarding state."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_stp']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    if 'stp' not in features:
        satisfied.append(name)
        return(satisfied, warnings)
    discarding = []
    for iface in features['stp']:
        if 'discarding' in features['stp'][iface]:
            discarding.append(iface)
            logger.debug('{} is in Discarding state!'.format(iface))
    if len(discarding) > 0:
        msg = ('STP-DISCARDING: STP state of Interface(s) {} is DISCARDING'
               .format(discarding))
        logger.debug(msg)
        warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_sub_int_bridge_vlan_collision(deprecated, satisfied, bridges, # noqa
                                         interfaces, subinterfaces, problems,
                                         warnings):
    """
    Check for sub/parent collision.

    # Check for sub-interfaces with a parent in a bridge that contains the
    # same VLAN.  See ZD 8251
    # To detect this condition, we iterate through each bridge to determine
    # if the parent of the subinterface is a member.  If so, we check to see
    # if the subinterface VLAN is also configured on the bridge.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems, warnings)
    reqs = ['discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems, warnings)
    for bridge in bridges:
        if 'vlans' not in interfaces[bridge]:
            if 'vlan-aware' in interfaces[bridge]:
                msg = ("NO-VLANS: Bridge [{}] does not have any VLANs "
                       "defined!".format(bridge))
                logger.debug(msg)
                warnings.append(msg)
            continue
        if 'bridge-ports' not in interfaces[bridge]:
            continue
        for subint in subinterfaces:
            if (interfaces[subint]['parent'] in
                    interfaces[bridge]['bridge-ports']):
                logger.debug(
                    'Found "{}" parent "{}" in bridge "{}" '
                    'bridge-ports.'.format(
                        subint, interfaces[subint]['parent'], bridge))
                vlanset = set(interfaces[subint]['vlans'])
                collision = vlanset.intersection(interfaces[bridge]['vlans'])
                if len(collision) > 0:
                    collision_list = []
                    for item in collision:
                        collision_list.append(item)
                    msg = ('CONFIG ERROR DETECTED: Sub-Interface [{}] parent '
                           '[{}] is member of bridge [{}] that is configured '
                           'with VLAN {}. See ZD 8251.'
                           .format(subint, interfaces[subint]['parent'],
                                   bridge, collision_list))
                    logger.debug(msg)
                    problems.append(msg)
    satisfied.append(name)
    return(satisfied, problems, warnings)


def detect_subint_misconfigs(deprecated, satisfied, interfaces, problems, # noqa
                             warnings):
    """
    Detect subint misconfigs.

    # Detect auto-created (missing) interfaces and possible conflict with
    # 802.1ad and 802.1q on the same physical interface as a result.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems, warnings)
    reqs = ['discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems, warnings)

    parents = {}
    for iface in interfaces:

        # Look for auto-created interfaces.
        if 'auto-created' in interfaces[iface]:
            msg = ("MISSING-CONFIG: Parent interface [{}] is missing! "
                   "Auto-created with vlan-protocol '802.1q' as parent of {}."
                   .format(iface, interfaces[iface]['orphans']))
            logger.debug(msg)
            warnings.append(msg)
        # Create list of parent interfaces with vlan-protocol set so we can
        # compare them to make sure there is no mix of 802.1ad and 802.1q on
        # the same physical interface.
        if 'vlan-protocol' not in interfaces[iface]:
            continue
        if 'parent' not in interfaces[iface]:
            continue
        vp = interfaces[iface]['vlan-protocol']
        parent = interfaces[iface]['parent']
        if parent not in parents:
            parents[parent] = {}
            parents[parent]['protocols'] = {}
        if vp not in parents[parent]['protocols']:
            parents[parent]['protocols'][vp] = []
        parents[parent]['protocols'][vp].append(iface)

    for parent in parents:
        if len(parents[parent]['protocols']) > 1:
            msg = ('VLAN-PROTOCOL-MISCONFIG: Interface [{}]: 802.1ad children:'
                   ' {} -- 802.1q children: {}. Only one vlan-protocol allowed'
                   ' on a physical interface!'
                   .format(parent,
                           parents[parent]['protocols']['802.1ad'],
                           parents[parent]['protocols']['802.1q']))
            logger.debug(msg)
            problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, problems, warnings)


def detect_sym_vxlan_on_spectrum_v0(deprecated, satisfied, discovered,
                                    features, warnings):
    """Detect Spectrum A0 ASIC in conjunction to VxLAN Symmetric Routing."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_vxlan_type', 'detect_mlx_smbios_error']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    if ('vxlan' in features and 'type' in features['vxlan'] and
            'Spectrum ASIC Version' in discovered):
        if (discovered['Spectrum ASIC Version'] == '0' and (
            features['vxlan']['type'] == 'Symmetric' or
                features['vxlan']['type'] == 'Centralized')):
            msg = ("UNSUPPORTED: VxLAN Symmetric Routing configured on "
                   "Spectrum A0 ASIC!")
            warnings.append(msg)
            logger.debug(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)

def detect_young_routes(deprecated, satisfied, info, young_routes):
    """Warn for young_routes."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, info)
    reqs = ['discover_young_routes']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, info)
    min_age = 10
    for prefix in young_routes:
        msg = ("YOUNG-ROUTE: '{}' is <= "
               "{} mins old."
               .format(prefix, min_age))
        logger.debug(msg)
        info.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, info)

def detect_tcp_rsyslog(deprecated, satisfied, discovered, warnings):
    """Detect remote syslog configuration using TCP and version below 3.6.0 (CM-19292)"""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_remote_syslog']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)

    if bool(discovered['remote_syslog']):
      cl_ver = discovered['os-release']
      cl_ver_split = cl_ver.split(".")

      if (int(cl_ver_split[0]) < 3):
          affected_version = True
      elif (int(cl_ver_split[0]) == 3 and int(cl_ver_split[1]) < 6):
          affected_version = True
      else:
          affected_version = False

      for server in discovered['remote_syslog']:
        #logger.debug("Remote syslog server protocol is {}".format(discovered['remote_syslog'][server]['protocol']))
        if (discovered['remote_syslog'][server]['protocol'] == "tcp" and affected_version == True):
          msg = ("Remote syslog server:{} configured with TCP transport, potential memory leak due to CM-19292".
          format(discovered['remote_syslog'][server]['ip']))
          warnings.append(msg)
          logger.debug(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)

def detect_test_pkgs(deprecated, satisfied, discovered, warnings):
    """Detect packages that are marked as 'testing' packages."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_dpkg']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)

    special_packages = {
        'bcm-sdk': ['6.5.14-cl3u24.1~testing', 'some-other-test-version']
    }

    for tp in special_packages:
        if tp in discovered['packages']:
            for ver in special_packages[tp]:
                if ver == discovered['packages'][tp]['version']:
                    msg = ('SPECIAL-PACKAGE: Package [{}] version [{}] '
                           'installed.'.format(tp, ver))
                    warnings.append(msg)

    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_route_leak_misconfig(deprecated, satisfied, discovered, features,
                                problems):
    """
    Detect route-leak misconfig.

    # Detect and warn about static route leaking when vrf_route_leak_enable
    # is not enabled in switchd.conf.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_frr_bgp_ip', 'discover_switchd_conf']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)

    # Which knobs are set?
    if ('vrf_route_leak_enable' not in discovered or 'TRUE' not in
            discovered['vrf_route_leak_enable']):
        static = False
    else:
        static = True
    if ('vrf_route_leak_enable_dynamic' not in discovered or 'TRUE' not in
            discovered['vrf_route_leak_enable_dynamic']):
        dynamic = False
    else:
        dynamic = True

    if static and dynamic:
        msg = ('UNSUPPORTED-CONFIG: Both static and dynamic route leaking '
               'are enabled in switchd.conf!  These two settings are '
               'mutually exclusive!')
        problems.append(msg)

    if 'static route leaking' in features and not static:
        vrfs = []
        for vrf in features['static route leaking']:
            vrfs.append(vrf)
        msg = ("STATIC-ROUTE-LEAKING-MISCONFIG: Static route leaking is "
               "configured in VRF {} but 'vrf_route_leak_enable' = FALSE!"
               .format(vrfs))
        logger.debug(msg)
        problems.append(msg)
    if 'dynamic route leaking' in features and not dynamic:
        msg = ("DYNAMIC-ROUTE-LEAKING-MISCONFIG: Dynamic route leaking is "
               "configured but 'vrf_route_leak_enable_dynamic' = FALSE!")

        logger.debug(msg)
        problems.append(msg)

    satisfied.append(name)
    return(satisfied, problems)


def detect_unlicensed(deprecated, satisfied, discovered, problems):
    """Detect and note that the switch is unlicensed."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, discovered, problems)
    reqs = ['discover_etc']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, discovered, problems)
    # Detect that we didn't find a license.
    if 'license' not in discovered:
        discovered['license'] = 'NO LICENSE FOUND!'
        problems.append('NO-LICENSE-FOUND: The switch appears to be '
                        'unlicensed!')
    satisfied.append(name)
    # Then, return:
    return(satisfied, discovered, problems)


def detect_unsupported_protocols(deprecated, satisfied, features, warnings):
    """
    Detect unsupported protocols.

    # Detect and warn when customer has configured protocols that are not
    # officially supported by Cumulus.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, warnings)
    reqs = ['discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, warnings)
    # Detect configured but non-supported protocols
    non_supported = ['babel', 'eigrp', 'isis', 'rip', 'ripng']
    for protocol in non_supported:
        if protocol in features:
            msg = ('UNSUPPORTED-PROTOCOL: Unsupported protocol [{}] is '
                   'configured but, unsupported!'
                   .format(protocol))
            logger.debug(msg)
            warnings.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, warnings)


def detect_unsupported_vx_routing(deprecated, satisfied, discovered, features, # noqa
                                  interfaces, problems, warnings):
    """
    Detect unsupported VxLAN config.

    # Detect when VXLAN routing is configured on platforms that do not
    # support it.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems, warnings)
    reqs = ['discover_vxlan_type', 'discover_platform_detail',
            'discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems, warnings)
    # Discovery or Detection code goes here...

    supported_asics = ['Maverick', 'Spectrum', 'Spectrum_A1', 'Tomahawk',
                       'Tomahawk+', 'Trident2+', 'Trident3', 'Trident3 X7']
    requires_hyperloop = ['Tomahawk', 'Tomahawk+']

    # Make sure we have the data we need for the detection.
    msg = ''
    nogo = False
    if 'vxlan' not in features:
        msg = 'No VxLAN routing config detected...'
        nogo = True
    if 'vxlan' in features and 'type' not in features['vxlan']:
        msg = 'VxLAN type not detected...'
        nogo = True
    if 'platform' not in discovered:
        msg = msg + ' Platform not detected...'
        nogo = True
    else:
        if 'device' not in discovered['platform']:
            msg = msg + ' Device not detected...'
            nogo = True
        else:
            if 'soc' not in discovered['platform']['device']:
                msg = msg + ' SOC not detected...'
                nogo = True
            else:
                if 'model' not in discovered['platform']['device']['soc']:
                    msg = msg + ' ASIC not detected...'
                    nogo = True
    # If something was missing, time to bail.
    if nogo:
        logger.debug(msg)
        return(satisfied, problems, warnings)
    # Now we can get to the business of detecting a problem.
    # We know that VxLAN routing of some sort is configured. Is our ASIC
    # one of the ones that support VxLAN routing?
    if discovered['platform']['device']['soc']['model'] not in supported_asics:
        msg = ('UNSUPPORTED-VXLAN-ROUTING: {} VxLAN is configured but not '
               'supported on {} ASIC!'
               .format(features['vxlan']['type'],
                       discovered['platform']['device']['soc']['model']))
        logger.debug(msg)
        problems.append(msg)

    # Do we have any contingencies?
    # Lets deal with Spectrum first...
    if 'Spectrum' in discovered['platform']['device']['soc']['model']:
        if 'Spectrum ASIC Version' not in discovered:
            msg = ('VXLAN-ROUTING: {} VxLAN is configured on Spectrum but '
                   'could not detect ASIC Version.'
                   .format(features['vxlan']['type']))
            logger.debug(msg)
            warnings.append(msg)
        else:
            if 'Spectrum' in discovered['platform']['device']['soc']['model']:
                if (discovered['Spectrum ASIC Version'] == '0' and
                        'Asymmetric' not in features['vxlan']['type']):
                    msg = ('UNSUPPORTED-VXLAN-ROUTING: {} VxLAN routing is '
                           'configured but not not supported on Spectrum A0!'
                           .format(features['vxlan']['type']))
                    logger.debug(msg)
                    problems.append(msg)
    # Now deal with our ASICs that require hyperloop.
    if (discovered['platform']['device']['soc']['model'] in
            requires_hyperloop):
        if 'hyperloop-ports' not in features:
            msg = ('UNSUPPORTED-VXLAN-ROUTING: {} VxLAN is configured but '
                   'requires hyperloop on {} ASIC!'
                   .format(features['vxlan']['type'],
                           discovered['platform']['device']['soc']['model']))
            logger.debug(msg)
            problems.append(msg)
        else:
            msg = ('HYPERLOOP: Port(s) {} configured as hyperloop.'
                   .format(features['hyperloop-ports']))
            logger.debug(msg)
            warnings.append(msg)
        # We also need a vlan-aware bridge for this to work when we require
        # hyperloop.
        vlan_aware = False
        # Iterate through  interfaces looking for a vlan-aware bridge.
        for iface in interfaces:
            if ('vlan-aware' in interfaces[iface] and
                    'is-bridge' in interfaces[iface]):
                vlan_aware = True
        if not vlan_aware and 'hyperloop-ports' in features:
            msg = ('UNSUPPORTED-VXLAN-ROUTING: {} VxLAN configured with '
                   'hyperloop on {} ASIC requires a vlan-aware bridge!'
                   .format(features['vxlan']['type'],
                           discovered['platform']['device']['soc']['model']))
            logger.debug(msg)
            problems.append(msg)
    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems, warnings)


def detect_vxlan_bad_path(deprecated, satisfied, discovered, problems, svis, # noqa
                          v4_routes):
    """Detect issues with paths to remote VTEPs (via SVI, subint or eth0)."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_v4_routes', 'discover_vnis']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if 'default' not in v4_routes:
        logger.debug('NO default routing table found!')
        return(satisfied, problems)
    # Some detections are only relevant on BCM.
    if 'chipset' in discovered:
        if ('Broadcom' in discovered['chipset'] or 'BCM' in
                discovered['chipset']):
            BCM = True
        else:
            BCM = False

    # Detection code goes here...
    #
    for vni in discovered['vnis']:
        # No remote VTEPs for the VNI? Continue
        if 'remote vteps' not in discovered['vnis'][vni]:
            continue
        # Iterate through the remote VTEPs
        for vtep in discovered['vnis'][vni]['remote vteps']:
            logger.debug('VNI {} -> VTEP {}'.format(vni, vtep))
            # A dict to hold the paths with the index being the mask...
            paths = {}
            # A list to hold the paths, sorted by longest match...
            paths2 = []
            # Iterate through our default routing table looking for all paths
            # to the remote VTEP held in 'vtep'...
            for subnet in v4_routes['default']:
                # If we find a path, add it to dict paths with its mask as
                # the key...
                if (ipaddress.ip_address(vtep) in
                   ipaddress.ip_interface(subnet).network):
                    mask = subnet.split('/')[1]
                    logger.debug('{} via {} mask {} -> {}'
                                 .format(vtep, subnet, mask,
                                         v4_routes['default'][subnet]))
                    paths[mask] = subnet
            # If we don't have any paths, that is a serious problem!
            if len(paths) < 1:
                msg = ('NO-PATH-TO-VTEP: No path to VTEP [{}] in VNI [{}]!'
                       .format(vtep, vni))
                logger.debug(msg)
                problems.append(msg)
                continue
            # Now that the dict of paths has been built, sort it in reverse
            # order, appending the paths to list paths2 so we can then get
            # the longest match path as paths2[0]...
            for key, value in sorted(paths.items(),
                                     key=lambda item: item[1], reverse=True):
                paths2.append(value)
            logger.debug('Best path = {} via {}'
                         .format(paths2[0], v4_routes['default'][paths2[0]]))
            # Finally, now that we know our longest match path to the remote
            # VTEP, we can look to see if its nexthop interface is a SVI, sub-
            # interface or eth0 which are both a bad thing!
            badnhint = False
            notfp = False
            viasvi = False
            for nhint in v4_routes['default'][paths2[0]]:
                # Is the path via a sub-interface?
                if '.' in nhint:
                    badnhint = True
                # Is the path via eth0?
                if 'eth0' in nhint:
                    notfp = True
                # Is the path via an SVI?
                if nhint in svis:
                    viasvi = True
            if badnhint and BCM:
                msg = ('VNI-PATH-VIA-SUB-INT: Route [{}] to VTEP [{}] in VNI '
                       '[{}] is via nexthop interface(s) {}!'
                       .format(paths2[0], vtep, vni,
                               v4_routes['default'][paths2[0]]))
                problems.append(msg)
            if notfp:
                msg = ('VNI-PATH-VIA-ETH0: Route [{}] to VTEP [{}] in VNI '
                       '[{}] is via non-fp port {}!'
                       .format(paths2[0], vtep, vni,
                               v4_routes['default'][paths2[0]]))
                problems.append(msg)
            if viasvi and BCM:
                msg = ('VNI-PATH-VIA-SVI: Route [{}] to VTEP [{}] in VNI '
                       '[{}] is via SVI {}!'
                       .format(paths2[0], vtep, vni,
                               v4_routes['default'][paths2[0]]))
                problems.append(msg)

    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)


def detect_wrong_onie_accton(deprecated, satisfied, discovered, problems):
    """Check for wrong ONIE. Re: ZD 8756."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, problems)
    reqs = ['discover_dmidecode', 'discover_platform']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, problems)
    if ('platform.detect' not in discovered or 'sysinfo' not in discovered or
            'Product Name' not in discovered['sysinfo']):
        logger.debug('Missing info required for check.')
        return(satisfied, problems)
    if 'Accton' not in discovered['sysinfo']['Manufacturer']:
        logger.debug('Not an Accton switch.')
        return(satisfied, problems)
    # Convert platform.detect to the same format that will be in Product Name.
    if ',' in discovered['platform.detect']:
        platform = discovered['platform.detect'].split(',')[1]
    else:
        platform = discovered['platform.detect']
    pf = platform.upper().replace('_', '-')
    prodname = discovered['sysinfo']['Product Name'].upper().replace('_', '-')
    if '-' in prodname:
        pns = prodname.split('-')
        pn = pns[0] + '-' + pns[1]
    else:
        pn = prodname
    logger.debug('pn = {} pf = {}'.format(pn, pf))
    if (pn not in pf) and (pf not in pn):
        msg = ('WRONG-ONIE: sysinfo: [{}] with platform.detect [{}]! '
               'See ZD 8756'
               .format(discovered['sysinfo']['Product Name'],
                       discovered['platform.detect']))
        logger.debug(msg)
        problems.append(msg)
    satisfied.append(name)
    # Then, return:
    return(satisfied, problems)
