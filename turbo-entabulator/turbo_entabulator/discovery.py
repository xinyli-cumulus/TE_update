#!/usr/bin/env python3
"""Turbo-Entabulator discovery."""

# Copyright(c) 2018, 2019 Cumulus Networks, Inc
# John Fraizer <jfraizer@cumulusnetworks.com>

import hashlib
import ipaddress
import json
import os
import re
import sys
from turbo_entabulator.utilities import check_dependencies, ifname_expand_glob
from turbo_entabulator.m_logger import logger

def discover_addresses(deprecated, satisfied, support_path):  # noqa
    # Discover local IP addresses.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, {})
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, {})
    filename = support_path + 'ip.addr'
    logger.debug(filename)
    # Verify that we can even open the file.
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, {})
    addresses = {}
    # Time to parse the file...
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if 'inet ' in stripped:
                vals = stripped.split()
                msg = ('Found [{}] on interface [{}]'
                       .format(vals[1], vals[-1]))
                logger.debug(msg)
                if not vals[-1] in addresses:
                    addresses[vals[-1]] = []
                addresses[vals[-1]].append(vals[1].split('/')[0])
    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, addresses)


def discover_bcm_counters(deprecated, satisfied, bcm_counters, support_path):
    """
    Iterate through show.counters to look for bcm counters we care about.

    # bcm_counters is a dict of dicts of lists.
    # The first dict is the counter.  It will contain a list of sdk_intf names
    # with the corresponding data for that interfaces counters.
    # Example:
    #
    # "bcm_counters": {
    #                "TDBGC5": {
    #                          "xe52": [
    #                                    "786,515,520",
    #                                    "+786,515,520",
    #                                    "211/s"
    #                          ],
    #                          "xe53": [
    #                                    "827,577,869",
    #                                    "+827,577,869",
    #                                    "166/s"
    #                          ]
    #                }
    #      }
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, bcm_counters)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, bcm_counters)
    filename = support_path + 'show.counters'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, bcm_counters)
    logger.debug("Parsing {}".format(filename))
    # Add counters we care about:
    counters = ['TDBGC5', 'TERR', 'RFRG', 'RFCS', 'RERPKT', 'MTUE']
    # Time to iterate through the file and collect the data.
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # if the line is a comment, we don't care about it!
            if not stripped.startswith('#'):
                # We will want to get rid of the first two fields when
                # we store the data in the list but, not before we capture
                # the counter and interface as vals2[0] and vals2[1] by
                # splitting vals1[0] on '.'
                vals1 = stripped.split()
                vals2 = vals1[0].split('.')
                # Iterate through our counters we care about to see if this
                # line contains data of interest.
                for counter in counters:
                    # If we have data we care about, we should store it!
                    if counter in vals2[0]:
                        logger.debug(vals1)
                        # If this is the first time we've seen this counter,
                        # we need to add it the counter dict to bcm_counters.
                        if counter not in bcm_counters:
                            bcm_counters[counter] = {}
                        # Now, we store all but the first two fields of vals1
                        bcm_counters[counter][vals2[1]] = vals1[2:]
    fh.close()
    satisfied.append(name)
    return (satisfied, bcm_counters)

def discover_bios(deprecated, satisfied, discovered, support_path): # noqa
    """Iterate through bios to discover bios details."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, discovered)
    filename = support_path + 'bios'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return(satisfied, discovered)
    logger.debug("Parsing {}".format(filename))
    # Fields we are interested in...
    fields = ['Vendor', 'Version', 'Release Date', 'BIOS Revision']
    discovered['bios'] = {}
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            for field in fields:
                if stripped.startswith(field):
                    field1 = field.split(':')[0]
                    logger.debug('Found field [{}].'.format(field1))
                    discovered['bios'][field1] = ' '.join(stripped.split(
                        field + ':')[1:]).strip()
    fh.close()
    satisfied.append(name)
    return(satisfied, discovered)


def discover_bridges(deprecated, satisfied, bridges, discovered, interfaces):
    """
    Discover bridges and bridge types.

    # Iterate over list of bridges and determine which are traditional vs
    # vlan_aware.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Discovery or Detection code goes here...
    #
    for bridge in bridges:
        logger.debug(interfaces[bridge])
        if ('vlan-aware' in interfaces[bridge] and
                interfaces[bridge]['vlan-aware']):
            logger.debug('Found VLAN-Aware bridge [{}]'.format(bridge))
            if 'vlan_aware_bridges' not in discovered:
                discovered['vlan-aware-bridges'] = []
            discovered['vlan-aware-bridges'].append(bridge)
        else:
            logger.debug('Found Traditional bridge [{}]'.format(bridge))
            if 'traditional-bridges' not in discovered:
                discovered['traditional-bridges'] = []
            discovered['traditional-bridges'].append(bridge)

    #
    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_clagd(deprecated, satisfied, features, support_path): # noqa
    """Discover clagd status."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['find_support_path', 'discover_ifquery']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    # We don't need to look for the status if clagd isn't configure.
    if 'clag' not in features:
        logger.debug('CLAGD is not configured.')
        return (satisfied, features)
    # If clagd-backup-ip is not configured, we can't check its status.
    if 'clagd-backup-ip' not in features['clag']:
        logger.debug('clagd-backup-ip is not configured.')
        satisfied.append(name)
        return (satisfied, features)
    # Verify that we can open the file.
    filename = support_path + 'clag.status'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, features)
    logger.debug("Parsing {}".format(filename))
    # Time to iterate through the file and collect the data.
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # if the line is a comment, we don't care about it!
            if not stripped.startswith('#'):
                if (stripped.startswith('Backup IP:') and '(active)'
                        in stripped):
                    features['clag']['clagd-backup-ip-status'] = 'active'
                if (stripped.startswith('Backup IP:') and '(inactive)'
                        in stripped):
                    features['clag']['clagd-backup-ip-status'] = 'inactive'
                if stripped.startswith('The peer is'):
                    if 'is alive' in stripped:
                        features['clag']['peer-alive'] = 'True'
                    if 'not alive' in stripped:
                        features['clag']['peer-alive'] = 'False'

    fh.close()
    if 'clagd-backup-ip-status' not in features['clag']:
        features['clag']['clagd-backup-ip-status'] = 'unknown'
    if 'peer-alive' not in features['clag']:
        features['clag']['peer-alive'] = 'Unknown'

    # Now checking clag.params file, to detect features for: traffic indirect
    # mode, neighSync and permanentMacSync
    filename = support_path + "clag.params"
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        satisfied.append(name)
        return (satisfied, features)
    logger.debug("Parsing {}".format(filename))
    # Checking if CLAG traffic indirect feature is enabled or not
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if line.startswith('#'):
                continue
            split = line.split()
            if len(split) < 2:
                continue
            logger.debug("reading line {}".format(line))
            if (split[0] == "redirectEnable"):
                features['clag']['redirectEnable'] = split[2]
            if (split[0] == "neighSync"):
                features['clag']['neighSync'] = split[2]
            if (split[0] == "permanentMacSync"):
                features['clag']['permanentMacSync'] = split[2]
            if (split[0] == "debug"):
                features['clag']['debug'] = split[2]
    fh.close()

    if 'redirectEnable' not in features['clag']:
        features['clag']['redirectEnable'] = 'False'

    satisfied.append(name)
    return (satisfied, features)


def discover_cmdline(deprecated, satisfied, CL, features):  # noqa
    """Read in /proc/cmdline to find spectre/meltdown settings."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    filename = CL + '/proc/cmdline'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, features)
    # If we see any of the following on the cmdline, it means that the kernel
    # was booted with that mitigation/patch enabled.
    options = ['noibrs', 'noibpb', 'nolfence', 'spectre_v2=off', 'nopti']

    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Check for forwarding being disabled.
            for option in options:
                if option not in stripped:
                    if 'Spectre/Meltdown Mitigation' not in features:
                        features['Spectre/Meltdown Mitigation'] = {}
                    features['Spectre/Meltdown Mitigation'][option] = True
    fh.close()
    satisfied.append(name)
    return (satisfied, features)


def discover_control(deprecated, satisfied, CL, discovered):  # noqa
    """Discover info from the Control file."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = CL + '/Control'
    logger.debug(filename)
    # Verify that we can even open the file.
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    # Time to parse the file...
    interested = ['Reason', 'Command line']
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            vals = stripped.split(':')
            if vals[0] in interested:
                discovered[vals[0]] = vals[1].strip()
        if 'Reason' not in discovered:
            discovered['Reason'] = 'Manually Generated'
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_cpld(deprecated, satisfied, discovered, support_path):
    """Discover CPLD versions."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'cpld'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered)
    logger.debug("Parsing {}".format(filename))
    my_string = []
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            logger.debug(stripped)
            if stripped.startswith('cpld') and '=' in stripped:
                logger.debug('Found field [{}].'.format(stripped))
                my_string.append(stripped)

            if len(my_string) > 0 and 'cpld_version' not in discovered:
                discovered['cpld_version'] = my_string

    fh.close()
    satisfied.append(name)
    return (satisfied, discovered)


def discover_date(deprecated, satisfied, discovered):
    """Discover the system date from the cl_support name."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)

    if 'cl_support' not in discovered['cl_support']:
        logger.debug("Unrecognized format for cl_support name: {}"
                     .format(discovered['cl_support']))
        return (satisfied, discovered)
    # Try to determine date from cl_support name.
    x = len(discovered['cl_support'].split('_'))
    y = discovered['cl_support'].split('_')[x - 2][:-4]
    m = discovered['cl_support'].split('_')[x - 2][-4:][:-2]
    d = discovered['cl_support'].split('_')[x - 2][-4:][-2:]
    discovered['system date'] = y + '-' + m + '-' + d
    satisfied.append(name)
    return (satisfied, discovered)


def discover_dhcrelay_conf(deprecated, satisfied, CL, services): # noqa
    """Parse the config files for dhcrelay service if it is enabled."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, services)
    reqs = ['discover_services']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, services)
    for service in services:
        if 'dhcrelay' in service and '6' not in service:
            for vrf in services['dhcrelay']['vrf']:
                if 'default' in vrf:
                    shortname = 'isc-dhcp-relay'
                else:
                    shortname = 'isc-dhcp-relay-' + vrf
                filename = CL + '/etc/default/' + shortname
                logger.debug(filename)
                # Verify that we can even open the file.
                if not os.path.isfile(filename):
                    logger.debug("Could not open {} .".format(filename))
                    if 'config' not in services[service]:
                        services[service]['config'] = {}
                        services[service]['config']['vrf'] = {}
                    services[service]['config']['vrf'][vrf] = (
                        'Config file [{}] not found!'.format(shortname))
                    # It is bad but, not enough to ignore other possible
                    # configs and return at this point!
                    continue
                # Time to parse the config...
                with open(filename, encoding='ISO-8859-1') as fh:
                    if 'config' not in services[service]:
                        services[service]['config'] = {}
                        services[service]['config']['vrf'] = {}
                    services[service]['config']['vrf'][vrf] = {}
                    for line in fh:
                        stripped = line.strip()
                        if not stripped.startswith('#'):
                            # Discover the servers.
                            if stripped.startswith('SERVERS'):
                                (services[service]['config']['vrf'][vrf]
                                 ['servers']) = (stripped.replace('"', '')
                                                 .split('=')[-1].split())
                            if stripped.startswith('INT'):
                                (services[service]['config']['vrf'][vrf]
                                 ['interfaces']) = (stripped.replace('"', '').
                                                    replace('-i', '').
                                                    split('=')[-1].split())
                            if stripped.startswith('OPTIONS'):
                                (services[service]['config']['vrf'][vrf]
                                 ['OPTIONS']) = (stripped.replace('"', '')
                                                 .split('=')[-1].split())
    satisfied.append(name)
    return (satisfied, services)


def discover_dpkg(deprecated, satisfied, discovered, support_path):  # noqa
    """Build a dict of installed packages and their versions."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'dpkg.installed'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered)
    logger.debug("Parsing {}".format(filename))

    # Build our regex to parse package lines...
    x = re.compile(r'(?P<s>ii\s+)(?P<p>\S+)\s+(?P<v>\S+)\s+(?P<a>\S+)\s+(?P<d>.*)')  # noqa

    # A dict to hold the parsed package information.
    discovered['packages'] = {}

    # Read in dpkg.installed and populate our dict...
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith('ii'):
                m = x.search(stripped)
                if m:
                    discovered['packages'][m.group('p')] = {}
                    discovered['packages'][m.group('p')]['version'] = (
                        m.group('v'))
                    discovered['packages'][m.group('p')]['arch'] = (
                        m.group('a'))

                    discovered['packages'][m.group('p')]['description'] = (
                        m.group('d'))

    fh.close()
    satisfied.append(name)
    return (satisfied, discovered)


def discover_dmidecode(deprecated, satisfied, discovered, support_path): # noqa
    """Parse dmidecode for various information."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the dmidecode.
    filename = support_path + 'dmidecode'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    discovered['sysinfo'] = {}
    # Open and parse dmidecode.
    section = False
    interested = ['Manufacturer:', 'Product Name:', 'Version:',
                  'Serial Number:', 'Family:', 'UUID!']
    msum = hashlib.md5()
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith('#') and ('umber:' in stripped
                                                 or 'Name:' in stripped
                                                 or 'UUID:' in stripped):
                msum.update(stripped.encode('utf-8'))
            if stripped.startswith('Handle 0x'):
                section = False
                if stripped.startswith('Handle 0x0001'):
                    section = True
            if section and ':' in stripped:
                for item in interested:
                    if stripped.startswith(item):
                        vals = stripped.split(':')
                        discovered['sysinfo'][item.split(':')[0]] = (
                            str(vals[1]).strip())
    fh.close()

    if 'eth0_mac' in discovered:
        msum.update(discovered['eth0_mac'].encode('utf-8'))

    discovered['sysinfo']['Unique-ID'] = msum.hexdigest().upper()

    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_etc(deprecated, satisfied, CL, discovered, features, services): # noqa
    """Discovery of info in various files in /etc/."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered, features)
    reqs = ['CL', 'find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, features)

    files = ['cumulus/.license', 'cumulus/.license.txt', 'cumulus/.license.vx',
             'cumulus/.license.rmp', 'hostname', 'image-release',
             'lsb-release', 'nsswitch.conf', 'os-release', 'rdnbrd.conf',
             'tacplus_servers', 'timezone', 'fstab', 'ptm.d/topology.dot',
             'bcm.d/datapath/datapath.conf']
    path = CL + "/etc/"
    for file in files:
        filename = path + file
        if os.path.isfile(filename):
            logger.debug("Parsing {}".format(filename))
            with open(filename, encoding='ISO-8859-1') as fh:
                for line in fh:
                    stripped = line.strip()
                    if 'license' in filename and 'license' not in discovered:
                        if len(stripped) > 0:
                            discovered['license'] = stripped
                    if 'hostname' in filename:
                        if len(stripped) > 0:
                            discovered['hostname'] = stripped
                    if 'image-release' in filename:
                        if 'IMAGE_RELEASE' in stripped:
                            _, image = stripped.split("=")
                            discovered['image-release'] = image
                        if 'IMAGE_SWITCH_ARCHITECTURE' in stripped:
                            _, arch = stripped.split("=")
                            discovered['switch-architecture'] = arch
                    if 'lsb-release' in filename:
                        if 'DISTRIB_RELEASE' in stripped:
                            _, lsb = stripped.split("=")
                            discovered['lsb-release'] = lsb
                    if 'os-release' in filename:
                        if 'VERSION_ID' in stripped:
                            _, version = stripped.split("=")
                            discovered['os-release'] = version
                    # If rdnbrd is enabled, get info about its config.
                    if ('rdnbrd' in filename and 'rdnbrd' in
                            services):
                        feature = 'rdnbrd'
                        services[feature]['description'] = (
                            "Redistribute Neighbor")
                        if "=" in stripped:
                            setting, val = stripped.split("=")
                        if stripped.startswith('loglevel'):
                            services[feature]['loglevel'] = val
                        if stripped.startswith('keepalive'):
                            services[feature]['keepalive'] = val
                        if stripped.startswith('holdtime'):
                            services[feature]['holdtime'] = val
                        if stripped.startswith('route_table'):
                            services[feature]['route_table'] = val
                        if stripped.startswith('debug_arp'):
                            services[feature]['debug_arp'] = val
                        if stripped.startswith('unicast_arp'):
                            services[feature]['unicast_arp_requests'] = val
                    if 'timezone' in filename:
                        if len(stripped) > 0:
                            discovered['timezone'] = stripped
                    if 'nsswitch.conf' in filename:
                        if (stripped.startswith('passwd') and 'tacplus' in
                                stripped):
                            if 'tacplus' not in features:
                                features['tacplus'] = {}
                            features['tacplus']['status'] = 'Enabled'
                    if 'tacplus_servers' in filename:
                        if stripped.startswith('vrf'):
                            if 'tacplus' not in features:
                                features['tacplus'] = {}
                            features['tacplus']['vrf'] = (stripped
                                                          .split('=')[-1])
                        if stripped.startswith('server'):
                            if 'tacplus' not in features:
                                features['tacplus'] = {}
                            if 'servers' not in features['tacplus']:
                                features['tacplus']['servers'] = []
                            features['tacplus']['servers'].append(
                                stripped.split('=')[-1])
                    if 'fstab' in filename:
                        if 'fstab' not in discovered:
                            discovered['fstab'] = []
                        if stripped.startswith('#'):
                            continue
                        if ' /' in stripped:
                            discovered['fstab'].append(stripped)
                    if 'topology.dot' in filename:
                        if 'graph G' in stripped:
                            if 'ptmd' not in features:
                                features['ptmd'] = {}
                            features['ptmd']['topology.dot'] = True
                    if 'datapath.conf' in filename:
                        if stripped.startswith('#'):
                            continue
                        if (stripped.startswith(
                                "vxlan_routing_overlay.profile") and
                                'disable' not in stripped):
                            if 'vxlan' not in features:
                                features['vxlan'] = {}
                            features['vxlan']['vxlan_routing_overlay.profile']\
                                = stripped.split('=')[1].strip()

            fh.close()
        else:
            logger.debug("ERROR: Could not open {}.".format(filename))
    # If lsb-release is different than image-release, it is a sure sign that
    # the device has been upgraded using apt-get.
    if 'lsb-release' in discovered and 'image-release' in discovered:
        if discovered['lsb-release'] != discovered['image-release']:
            discovered['upgraded with apt-get'] = True

    if 'license' in discovered and 'If it is removed' in discovered['license']:
        discovered['license'] = 'Switch is licensed as an RMP'

    satisfied.append(name)
    return (satisfied, discovered, features)


def discover_ethtool_stats(deprecated, satisfied, interfaces, support_path):
    """
    Discover the ethtool stats.

    # Collect the statistics for interfaces so we can calculate the % Drops
    # on each interface.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, interfaces)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, interfaces)
    filename = support_path + 'ethtool.stats'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, interfaces)
    logger.debug("Parsing {}".format(filename))
    # Speficy the fields that we sum to get total packets.
    pkts = ['HwIfInUcastPkts', 'HwIfInBcastPkts', 'HwIfInMcastPkts',
            'HwIfOutUcastPkts', 'HwIfOutMcastPkts', 'HwIfOutBcastPkts', ]
    # Speficy the discard fields.
    discards = ['HwIfInDiscards', 'HwIfOutDiscards']
    # All of the fields!
    fields = pkts + discards
    # Time to populate interfaces with the data from the fields.
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if "ethtool -S" in stripped:
                iface = stripped.split()[-1]
                if iface not in interfaces:
                    interfaces[iface] = {}
            else:
                for field in fields:
                    if 'iface' in locals() and stripped.startswith(field):
                        field_value = stripped.split()[1]
                        interfaces[iface][field] = int(field_value)
    fh.close()
    satisfied.append(name)
    return (satisfied, interfaces)


def discover_eth0(deprecated, satisfied, discovered, support_path):
    """Parse ip.link to get eth0 MAC."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'ip.link'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    # Open and parse ip.link.
    stage = False
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if 'eth0:' in stripped:
                stage = True
            if 'link/ether' in stripped and stage:
                eth0_mac = stripped.split('ether')[1].split()[0]
                discovered['eth0_mac'] = eth0_mac
                break
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_evpn_routes(deprecated, satisfied, discovered, support_path): # noqa
    """
    Discover evpn routes.

    # *> [2]:[0]:[0]:[48]:[00:60:16:99:6e:25]:[32]:[10.37.146.81]
    #                    10.37.254.34                           0 4219750110 4219750211 i # noqa
    #                    RT:18243:72146 RT:18243:379999 ET:8 Rmac:44:38:39:ff:00:18 # noqa
    # Becomes...
    # "evpn_routes": {
    #         "10.37.146.81/32": {
    #                     "nexthop": "10.37.254.34",
    #                     "type": "2"
    #         },
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'bgp.evpn.route'
    # Verify that we can even open the file.
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)

    logger.debug('Parsing: {}'.format(filename))
    if 'evpn_routes' not in discovered:
        discovered['evpn_routes'] = {}
    # This is a bool to determine if we're looking for a nexthop or a
    # route.
    logger.debug('Clearing nh_search...')
    nh_search = False
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith('*'):
                nh_search = False
            # Look for type-2 routes
            # *> [2]:[0]:[0]:[48]:[00:60:16:99:6e:25]:[32]:[10.37.146.81]
            # Look for type-5 routes:
            # *> [5]:[0]:[0]:[27]:[10.37.130.0]
            m = False
            if not nh_search:
                m = re.search('> \[(?P<type>[2])\]:\[.+\]:\[(?P<mask>\d+)'  # noqa
                              '\]:\[(?P<prefix>\d+\.\d+\.\d+\.\d+)\]',  # noqa
                              stripped)
            if m:
                # We found a Type-2 or Type-5 route.  Toggle the nh_search bool
                nh_search = True
                # We want to store the route as prefix/mask.
                route = m.group('prefix') + '/' + m.group('mask')
                type = m.group('type')
            # If we've found a route, we need to look for its nexthop.
            if nh_search:
                n = False
                n = re.search("^(?P<match>\d+\.\d+\.\d+\.\d+)\s", stripped)  # noqa
                # We found a nexthop.  Time to add it to the dict.
                if n:
                    if route not in discovered['evpn_routes']:
                        discovered['evpn_routes'][route] = {}
                        discovered['evpn_routes'][route]['nexthop'] = (
                            n.group('match'))
                        discovered['evpn_routes'][route]['type'] = type

    fh.close()

    # This is just some wedge code to get some stats during devel.
    nexthops = []
    for route in discovered['evpn_routes']:
        nexthop = discovered['evpn_routes'][route]['nexthop']
        if nexthop not in nexthops:
            nexthops.append(nexthop)
    logger.debug('Total Type[25]: {} Nexthops: {}'
                 .format(len(discovered['evpn_routes']), len(nexthops)))

    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_frr_bgp_ip(deprecated, satisfied, discovered, frr_path, features, # noqa
                        forwarding):
    """Parse ?.show_running for BGP features in use."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered, features, forwarding)
    reqs = ['find_frr_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, features, forwarding)
    if not os.path.isfile(frr_path):
        logger.debug("Unable to open {} to parse FRR data!".format(frr_path))
        return (satisfied, discovered, features, forwarding)
    logger.debug("Parsing {} for BGP".format(frr_path))
    st = []
    with open(frr_path, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()

            # We're already parsing the config file so, might as well look
            # for ip/ipv6 forwarding being disabled here.
            if stripped.startswith("no ip forwarding"):
                if 'FRR' not in forwarding:
                    forwarding['FRR'] = {}
                forwarding['FRR']['ip forwarding'] = 'Disabled'
            if stripped.startswith("no ipv6 forwarding"):
                if 'FRR' not in forwarding:
                    forwarding['FRR'] = {}
                forwarding['FRR']['ipv6 forwarding'] = 'Disabled'

            # Detect that we are at a new main section of config.
            if line.startswith("!"):
                st = []

            # Detect that we have dropped down one config level.
            if stripped.startswith("!") and len(st) > 2:
                del st[-1]

            # Detect PBR.
            if line.startswith('pbr-map'):
                if 'pbr' not in features:
                    features['pbr'] = {}
                if 'pbr-maps' not in features['pbr']:
                    features['pbr']['pbr-maps'] = []
                if stripped.split()[1] not in features['pbr']['pbr-maps']:
                    features['pbr']['pbr-maps'].append(stripped.split()[1])

            # Detect interface stanzas.
            if line.startswith("interface "):
                vals = stripped.split()
                st.append(vals[0])
                st.append(vals[1])
                vals = ''

            # Detect global router-id.
            if line.startswith('router-id'):
                router_id = line.split()[-1]
                features['global router-id'] = router_id

            # Detect BGP router-id.
            if 'bgp' in st and stripped.startswith('bgp router-id'):
                features[st[0]][st[1]]['router-id'] = stripped.split()[-1]

            # Detect bgp listen range
            if 'bgp' in st and stripped.startswith('bgp listen range'):
                features[st[0]][st[1]]['bgp-listen-range'] = ' '.join(
                    stripped.split()[3:])

            # Detect bgp bestpath
            if 'bgp' in st and stripped.startswith('bgp bestpath'):
                if 'bgp bestpath' not in features[st[0]][st[1]]:
                    features[st[0]][st[1]]['bgp bestpath'] = []
                if (' '.join(stripped.split()[2:]) not in
                        features[st[0]][st[1]]['bgp bestpath']):
                    features[st[0]][st[1]]['bgp bestpath'].append(
                        ' '.join(stripped.split()[2:]))

            # Detect BGP max-med.
            if 'bgp' in st and stripped.startswith('bgp max-med'):
                if 'max-med' not in features[st[0]][st[1]]:
                    features[st[0]][st[1]]['max-med'] = []
                features[st[0]][st[1]]['max-med'].append(
                    ' '.join(stripped.split()[2:]))

            # Detect referenced route-maps.
            if ('bgp' in st and 'route-map' in stripped
                    and (stripped.startswith('neighbor')
                         or stripped.startswith('redistribute'))):
                if 'redistribute' in stripped:
                    rm = stripped.split()[-1].strip()
                else:
                    rm = stripped.split()[-2].strip()
                logger.debug('Found reference to route-map {}.'.format(rm))
                if 'referenced route-maps' not in discovered:
                    discovered['referenced route-maps'] = []
                    logger.debug('Adding referenced route-maps')
                if rm not in discovered['referenced route-maps']:
                    logger.debug("Adding {} to referenced route-maps".format(
                        rm))
                    discovered['referenced route-maps'].append(rm)

            # Detect referenced prefix-lists:
            if ('bgp' in st and 'prefix-list' in stripped
                    and (stripped.startswith('neighbor')
                         or stripped.startswith('redistribute'))):
                if 'redistribute' in stripped:
                    pl = stripped.split()[-1].strip()
                else:
                    pl = stripped.split()[-2].strip()
                logger.debug('Found reference to prefix-list {}.'.format(pl))
                if 'referenced prefix-lists' not in discovered:
                    discovered['referenced prefix-lists'] = {}
                    discovered['referenced prefix-lists']['bgp'] = []
                    logger.debug('Adding referenced prefix-lists')
                if pl not in discovered['referenced prefix-lists']:
                    logger.debug("Adding {} to referenced prefix-lists".format(
                        pl))
                    discovered['referenced prefix-lists']['bgp'].append(pl)
            # Look for route-map matches that reference prefix-lists.
            if 'match' in stripped and 'prefix-list' in stripped:
                if 'referenced prefix-lists' not in discovered:
                    discovered['referenced prefix-lists'] = {}
                pl = stripped.split()[4]
                logger.debug(stripped)
                if ('route-map' not in
                        discovered['referenced prefix-lists']):
                    logger.debug(
                        'Creating route-map in referenced prefix-lists')
                    discovered['referenced prefix-lists']['route-map'] = {}
                if 'ipv6' in stripped:
                    if ('ipv6' not in
                            (discovered['referenced prefix-lists']
                                       ['route-map'])):
                        (discovered['referenced prefix-lists']
                                   ['route-map']['ipv6']) = []
                    (discovered['referenced prefix-lists']
                               ['route-map']['ipv6']).append(pl)
                else:
                    if ('ip' not in
                            (discovered['referenced prefix-lists']
                                       ['route-map'])):
                        (discovered['referenced prefix-lists']
                                   ['route-map']['ip']) = []
                    (discovered['referenced prefix-lists']
                               ['route-map']['ip']).append(pl)

            # Discover configured prefix-lists.
            if stripped.startswith('ip') and 'prefix-list' in stripped:
                if 'prefix-lists' not in discovered:
                    discovered['prefix-lists'] = {}
                    discovered['prefix-lists']['ip'] = []
                    discovered['prefix-lists']['ipv6'] = []
                pl = stripped.split()[2]
                if 'ipv6' in stripped:
                    if pl not in discovered['prefix-lists']['ipv6']:
                        discovered['prefix-lists']['ipv6'].append(pl)
                else:
                    if pl not in discovered['prefix-lists']['ip']:
                        discovered['prefix-lists']['ip'].append(pl)

            # Detect actual route-maps.
            if stripped.startswith('route-map'):
                if 'route-maps' not in discovered:
                    discovered['route-maps'] = []
                rm = stripped.split()[1].strip()
                if rm not in discovered['route-maps']:
                    logger.debug('Found route-map {}.'.format(rm))
                    discovered['route-maps'].append(rm)

            # Detect ip and ipv6 addresses
            if len(st) > 1 and st[0] == 'interface':
                if 'ip address' in stripped:
                    if 'FRR v4 addresses' not in features:
                        features['FRR v4 addresses'] = {}
                    if not st[1] in features['FRR v4 addresses']:
                        features['FRR v4 addresses'][st[1]] = []
                        vals = stripped.split()
                        features['FRR v4 addresses'][st[1]].append(vals[-1])
                    logger.debug(stripped)
                if 'ipv6 address' in stripped:
                    if 'FRR v6 addresses' not in features:
                        features['FRR v6 addresses'] = {}
                    if not st[1] in features['FRR v6 addresses']:
                        features['FRR v6 addresses'][st[1]] = []
                        vals = stripped.split()
                        features['FRR v6 addresses'][st[1]].append(vals[-1])
                    logger.debug(stripped)
                if 'ptm-enable' in stripped:
                    if 'ptmd' not in features:
                        features['ptmd'] = {}
                    if 'check-link-state' not in features['ptmd']:
                        features['ptmd']['check-link-state'] = []
                    features['ptmd']['check-link-state'].append(st[1])
                if 'pbr-policy' in stripped:
                    if 'pbr' not in features:
                        features['pbr'] = {}
                        features['pbr']['interfaces'] = {}
                    features['pbr']['interfaces'][st[1]] = stripped.split()[1]

            # Discover configured but non-supported protocols
            non_supported = ['babel', 'eigrp', 'isis', 'rip', 'ripng']
            if 'router' in stripped:
                vals = stripped.split()
                if vals[1] in non_supported:
                    if vals[1] not in features:
                        features[vals[1]] = 'CONFIGURED - UNSUPPORTED'

            # Detect BGP top-level config.
            if "router bgp" in stripped:
                st.append("bgp")
                if "bgp" not in features:
                    features['bgp'] = {}

                # Differentiate BGP in a VRF vs default.
                if "vrf" in stripped:
                    st.append("vrf")
                    if 'vrf' not in features['bgp']:
                        features['bgp']['vrf'] = {}
                elif 'view' in stripped:
                    view = "default: view " + stripped.split("view")[1].strip()
                    st.append(view)
                    if view not in features['bgp']:
                        features['bgp'][view] = {}
                else:
                    st.append("default")
                    if "default" not in features['bgp']:
                        features['bgp']['default'] = {}

            if 'bgp' in st and stripped.startswith("address-family"):
                if 'address-family' not in st:
                    st.append("address-family")
                    if not st[-1] in features[st[0]][st[1]]:
                        features[st[0]][st[1]][st[2]] = {}
                # Now determine which address family we're in...
                af = stripped.split(' ', 1)[1]
                st.append(af)
                # If we don't have an entry for this AF yet, add it...
                if not st[-1] in features[st[0]][st[1]][st[2]]:
                    features[st[0]][st[1]][st[2]][st[3]] = {}

            # Detect BGP unnumbered configuration
            if (stripped.startswith("neighbor") and "interface" in stripped
                    and 'bgp' in st):
                if 'unnumbered' not in st:
                    st.append("unnumbered")
                if st[-1] not in features[st[0]][st[1]]:
                    features[st[0]][st[1]][st[2]] = []
                # Determine which type and add it to the list if necessary.
                for type in ['external', 'internal', 'peer-group']:
                    if (type in stripped and type not in
                            features[st[0]][st[1]][st[2]]):
                        features[st[0]][st[1]][st[2]].append(type)

            # Detect IPv6 GUA peers
            if (stripped.startswith("neighbor") and ":" in stripped and 'bgp'
                    in st):
                peer = stripped.split()[1]
                try:
                    if ipaddress.ip_address(peer):
                        if 'IPv6 GUA Peers' not in features:
                            features['IPv6 GUA Peers'] = {}
                        if peer not in features['IPv6 GUA Peers']:
                            features['IPv6 GUA Peers'][peer] = stripped

                except ValueError:
                    logger.debug('Value Error checking {}'.format(stripped))

            # Detect extended nexthop
            if (stripped.startswith("neighbor") and "extended-next" in stripped
                    and 'bgp' in st):
                if 'extended-nexthop' not in features[st[0]][st[1]]:
                    features[st[0]][st[1]]['extended-nexthop'] = {}

            # Detect redistribution of protocols
            if stripped.startswith("redistribute") and 'address-family' in st:
                if 'redistribute' not in features[st[0]][st[1]][st[2]][st[3]]:
                    features[st[0]][st[1]][st[2]][st[3]]['redistribute'] = []
                redistribute = stripped.split()
                if (not redistribute[1] in
                        features[st[0]][st[1]][st[2]][st[3]]['redistribute']):
                    (features[st[0]][st[1]][st[2]][st[3]]['redistribute']
                     .append(redistribute[1]))

            # Detect BFD in BGP
            if (stripped.startswith("neighbor") and 'bfd' in stripped and 'bgp'
                    in st):
                if 'bfd' not in features[st[0]][st[1]]:
                    features[st[0]][st[1]]['bfd'] = {}

            # Detect various knobs in BGP address-families
            for knob in ['advertise-all-vni', 'advertise-default-gw',
                         'aggregate-address', 'maximum-paths', 'network',
                         'next-hop-self', 'router-id', 'route-map',
                         'soft-reconfiguration', 'maximum-prefix',
                         'filter-list', 'prefix-list', 'route-target export',
                         'route-target import', 'import vrf']:
                if knob in stripped and 'address-family' in st:
                    if (knob not in
                            features[st[0]][st[1]][st[2]][st[3]]):
                        (features[st[0]][st[1]][st[2]][st[3]]
                                 [knob]) = {}
                    if 'import vrf' in knob:
                        features['dynamic route leaking'] = True

            # Detect VRF sections
            if stripped.startswith("vrf "):
                st = stripped.split()
                if 'VRFs' not in features:
                    features['VRFs'] = []
                if not st[-1] in features['VRFs']:
                    features['VRFs'].append(st[-1])
            # Detect L3 VNIs
            if 'vrf' in st and stripped.startswith("vni"):
                if 'vxlan' not in features:
                    features['vxlan'] = {}
                if 'l3 vnis' not in features['vxlan']:
                    features['vxlan']['l3 vnis'] = {}
                data = stripped.split()
                features['vxlan']['l3 vnis'][data[1]] = st[-1]

            # Detect static route leaking in VRFs.
            if 'vrf' in st and 'nexthop-vrf' in stripped:
                if 'static route leaking' not in features:
                    features['static route leaking'] = {}
                features['static route leaking'][st[-1]] = []
                features['static route leaking'][st[-1]].append(stripped)

            # The following is simply for debugging.
            if len(st) >= 0:
                logger.debug("({}) - {}".format(st, stripped))

    fh.close()
    satisfied.append(name)
    return (satisfied, discovered, features, forwarding)


def discover_frr_ospf(deprecated, satisfied, frr_path, features): # noqa
    """Parse ?.show_running for BGP features in use."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['find_frr_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    if not os.path.isfile(frr_path):
        logger.debug("Unable to open {} to parse FRR data!".format(frr_path))
        return (satisfied, features)
    logger.debug("Parsing {} for OSPF".format(frr_path))
    st = []
    with open(frr_path, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Detect that we are at a new main section of config.
            if line.startswith("!"):
                st = []

            # Detect that we have dropped down one config level.
            if stripped.startswith("!") and len(st) > 2:
                del st[-1]

            # Detect BFD for ospf-v2
            if stripped.startswith("ip ospf bfd"):
                if 'ospf-v2' not in features:
                    features['ospf-v2'] = {}
                if 'bfd' not in features['ospf-v2']:
                    features['ospf-v2']['bfd'] = {}

            # Detect BFD for ospf-v3
            if stripped.startswith("ipv6 ospf6 bfd"):
                if 'ospf-v3' not in features:
                    features['ospf-v3'] = {}
                if 'bfd' not in features['ospf-v3']:
                    features['ospf-v3']['bfd'] = {}

            # Detect OSPFv2 top-level config.
            if "router ospf" in stripped:
                if 'ospf6' in stripped:
                    ver = 'ospf-v3'
                else:
                    ver = 'ospf-v2'
                st.append(ver)

                if ver not in features:
                    features[ver] = {}

                # Differentiate BGP in a VRF vs default.
                if "vrf" in stripped:
                    st.append('vrf')
                    if 'vrf' not in features[ver]:
                        features[ver]['vrf'] = {}
                else:
                    st.append("default")
                    if "default" not in features[ver]:
                        features[ver]['default'] = {}

            # Detect redistribution of protocols
            if (stripped.startswith("redistribute") and ('ospf-v2' in st or
                                                         'ospf-v3' in st)):
                if 'redistribute' not in features[st[0]][st[1]]:
                    features[st[0]][st[1]]['redistribute'] = []
                redistribute = stripped.split()
                if (redistribute[1] not in
                        features[st[0]][st[1]]['redistribute']):
                    (features[st[0]][st[1]]['redistribute']
                     .append(redistribute[1]))

            # Detect ospf-v2 router-id:
            if (stripped.startswith('ospf router-id') and 'ospf-v2' in st):
                rid = stripped.split()
                features[st[0]][st[1]]['router-id'] = rid[-1]

            # Detect ospf-v3 router-id:
            if (stripped.startswith('ospf6 router-id') and 'ospf-v3' in st):
                rid = stripped.split()
                features[st[0]][st[1]]['router-id'] = rid[-1]

            # Detect various knobs in OSPF
            for knob in ['abr-type cisco', 'abr-type ibm', 'abr-type shortcut',
                         'abr-type standard', 'auto-cost', 'default-cost',
                         'export-list', 'default-information-originate',
                         'default-metric', 'distance', 'distribute-list',
                         'filter-list', 'import-list', 'max-metric router-lsa',
                         'network', 'no router zebra', 'not-advertise',
                         'no ospf rfc1583compatibility', 'passive-interface',
                         'priority', ' range ', 'retransmit interval',
                         'route-map', 'shortcut', 'substitute',
                         'transmit-delay', 'virtual-link']:
                if knob in stripped and ('ospf-v2' in st or 'ospf-v3' in st):
                    if (knob not in features[st[0]][st[1]]):
                        (features[st[0]][st[1]][knob.strip()]) = {}

            # The following is simply for debugging.
            if len(st) >= 0:
                logger.debug("({}) - {}".format(st, stripped))
    satisfied.append(name)
    return (satisfied, features)


def discover_ifquery(deprecated, satisfied, ifquery_path, bridges, bonds, # noqa
                     features, interfaces, problems, subinterfaces, svis,
                     vlans_inuse):
    """Discover bridges, interfaces, subinterfaces, vlans.

    # Iterate through all interfaces reported in ifquery -a to discover:
    # Bridges (members and VLANs), interfaces (VLANs) and sub-subinterfaces
    # and their associated VLAN.
    # Parse ?.show_running for BGP features in use.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, bridges, bonds, features, interfaces, problems,
                subinterfaces, svis, vlans_inuse)
    reqs = ['find_ifquery_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, bridges, bonds, features, interfaces, problems,
                subinterfaces, svis, vlans_inuse)
    if not os.path.isfile(ifquery_path):
        logger.debug("Unable to open {} to parse!".format(ifquery_path))
        return (satisfied, bridges, bonds, features, interfaces, problems,
                subinterfaces, svis, vlans_inuse)

    logger.debug("Parsing {}".format(ifquery_path))
    vxlan = 0
    vxlan_addr = 0
    with open(ifquery_path, encoding='ISO-8859-1') as fh:
        for line in fh:

            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            # Ignore error lines.
            if 'error' in stripped:
                continue
            # If a line starts with "auto", we know we are looking
            # at a new interface stanza.
            if stripped.startswith("iface"):
                bridgeports = []
                bondslaves = []
                parent = ''
                inner_tag = ''
                result = []
                iface = stripped.split(" ")[1]
                check_vxlan = False
                # A "." in an interface name indicates a sub-
                # interface with the left side being the parent
                # interface and the right side being the VLAN.
                if "." in iface:
                    subs = iface.split(".")
                    try:
                        parent = subs[0]
                        subint = subs[1]
                        if len(subs) > 2:
                            inner_tag = subs[2]
                            if isinstance(int(inner_tag), int):
                                logger.debug("Found Inner VLAN Tag {} on {}"
                                             .format(inner_tag, iface))
                        if isinstance(int(subint), int):
                            logger.debug("Found VLAN {} on {}"
                                         .format(subint, iface))
                            result.append(int(subint))
                    except:  # noqa
                        pass

            # Detect SVIs...
            if stripped.startswith('vlan-raw-device'):
                if iface not in svis:
                    svis[iface] = stripped.split('vlan-raw-device')[1]

            # Detect LNV config.
            if stripped.startswith('vxrd'):
                if 'LNV' not in features:
                    features['LNV'] = {}
                features['LNV'][stripped.split()[0]] = stripped.split()[1]

            # Check for ip-forwarding being disabled on the iface.
            if 'ip-forward' in stripped:
                data = stripped.split()
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['ip-forward'] = data[1]

            # Check for ip-forwarding being disabled on the iface.
            if 'ip6-forward' in stripped:
                data = stripped.split()
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['ip6-forward'] = data[1]

            # Check for clagd-vxlan-anycast-ip
            if "clagd-vxlan-anycast-ip" in stripped:
                data = stripped.split()
                if 'vxlan' not in features:
                    features['vxlan'] = {}
                (features['vxlan']['clagd-vxlan-anycast-ip']) = data[1]

            # Check for vxlan-id on interface
            if "vxlan-id" in stripped:
                data = stripped.split()
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['vxlan-id'] = data[1]

            # Check for vxlan-id on interface
            if "vxlan-local-tunnelip" in stripped:
                data = stripped.split()
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['vxlan-local-tunnelip'] = data[1]

            # Parse VLANs from the interface.
            if ("bridge-pvid" in stripped or "bridge-vids" in stripped or
                    "bridge-access" in stripped):
                if iface not in interfaces:
                    interfaces[iface] = {}
                # Build a list from the line.
                commas = stripped.replace(',', ' ')
                components = commas.split()
                # Iterate through the list elements, ignoring the
                # "bridge-" keyword.
                for component in components[1:]:
                    # If we encounter a glob, convert it to a range.
                    if '-' in component:
                        # This is a range.
                        start, end = map(int, component.split('-'))
                        result.extend(range(start, end + 1))
                    else:
                        # Otherwise, its a single VLAN.
                        try:
                            if isinstance(int(component), int):
                                result.append(int(component))
                        except:  # noqa
                            pass
                logger.debug("Found VLAN(s) {} on {}"
                             .format(result, iface))
                for item in result:
                    if item not in vlans_inuse:
                        vlans_inuse.append(item)
            if 'vlan-id' in stripped:
                result.append(int(stripped.split()[-1]))
                logger.debug("Found VLAN(s) {} on {}"
                             .format(result, iface))
                for item in result:
                    if item not in vlans_inuse:
                        vlans_inuse.append(item)

            # Look for bridge-pvid or bridge-access to track CM-26383
            # vulnerability.
            if 'bridge-pvid' in stripped:
                interfaces[iface]['bridge-pvid'] = True
            if 'bridge-access' in stripped:
                interfaces[iface]['bridge-access'] = True

            # Parse members from the bridge-ports line:
            if "bridge-ports" in stripped:
                # Build a list from the line.
                components = stripped.split()
                components2 = []
                glob = False
                # Get rid of keyword and the word 'glob' if it exists while
                # tracking the fact that a glob follows.
                for component in components[1:]:
                    if 'glob' in component:
                        glob = True
                        continue
                    # Get rid of trailing ',' in component.
                    if component.endswith(','):
                        component = component[:-1]
                    # If this is a glob, process it as such...
                    if glob:
                        glob = False
                        globs = ifname_expand_glob(component)
                        for element in globs:
                            components2.append(element)
                    else:
                        components2.append(component)
                bridgeports = components2
                logger.debug("Found bridge-ports {} on {}"
                             .format(bridgeports, iface))

            # Parse slaves from the bond-slaves line:
            if "bond-slaves" in stripped:
                # Build a list from the line.
                components = stripped.split()
                components2 = []
                glob = False
                # Get rid of keyword and the word 'glob' if it exists while
                # tracking the fact that a glob follows.
                for component in components[1:]:
                    if 'glob' in component:
                        glob = True
                        continue
                    # Get rid of trailing ',' in component.
                    if component.endswith(','):
                        component = component[:-1]
                    # If this is a glob, process it as such...
                    if glob:
                        glob = False
                        globs = ifname_expand_glob(component)
                        for element in globs:
                            components2.append(element)
                    else:
                        components2.append(component)
                bondslaves = components2
                logger.debug("Found bond-slaves {} on {}"
                             .format(bondslaves, iface))

            # Parse bridge-aging time from bridge-aging line:
            if 'bridge-ageing' in stripped:
                bridge_ageing = stripped.split()[-1]
                logger.debug("Found bond-ageing [{}] on {}"
                             .format(bridge_ageing, iface))

            # Discover vlan-aware
            if 'bridge-vlan-aware yes' in stripped:
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['vlan-aware'] = True

            # Parse IP addresses from interfaces:
            if ('address ' in stripped and 'hw' not in stripped and 'post'
                    not in stripped):
                address = stripped.split()[1]
                if iface not in interfaces:
                    interfaces[iface] = {}
                # if not 'address' in interfaces[iface]:
                #    interfaces[iface]['address'] = []
                # interfaces[iface]['address'].append(address)
                try:
                    raw = ipaddress.ip_address(address.split('/')[0])
                    version = raw.version
                    if version == 4:
                        interfaces[iface]['address'] = address
                    if version == 6:
                        interfaces[iface]['address6'] = address
                except:  # noqa
                    msg = ('INVALID ADDRESS: [{}] on [{}] appears to be '
                           'invalid!'.format(address, iface))
                    logger.debug(msg)
                    problems.append(msg)

            # Parse VRR addresses.
            if 'address-virtual' in stripped:
                address = stripped.split()[2:]
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['address-virtual'] = address
                if 'vrr' not in features:
                    features['vrr'] = []
                if iface not in features['vrr']:
                    features['vrr'].append(iface)
                msg = ('Found VRR address(es) {} on [{}].'
                       .format(address, iface))
                logger.debug(msg)

            # Parse VRFs:
            if stripped.startswith('vrf '):
                if 'VRFs' not in features:
                    features['VRFs'] = []
                st = stripped.split()
                if not st[-1] in features['VRFs']:
                    features['VRFs'].append(st[-1])
                # Add the VRF indicator to the interface.
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['vrf'] = st[-1]

            # Parse CLAG parameters:
            clag_params = ['clagd-peer-ip', 'clagd-backup-ip', 'clagd-sys-mac',
                           'clagd-priority']
            for clag_param in clag_params:
                if stripped.startswith(clag_param):
                    if 'clag' not in features:
                        features['clag'] = {}
                    features['clag']['peerlink'] = iface
                    vals = stripped.split()
                    features['clag'][clag_param] = ' '.join(vals[1:])

            if stripped.startswith('clag-id'):
                if iface not in interfaces:
                    interfaces[iface] = {}
                if 'clag' not in features:
                    features['clag'] = {}
                if 'interfaces' not in features['clag']:
                    features['clag']['interfaces'] = []
                vals = stripped.split()
                interfaces[iface]['clag-id'] = vals[-1]
                features['clag']['interfaces'].append(iface)

            # Discover LACP config.
            if stripped.startswith('bond-lacp'):
                if iface not in interfaces:
                    interfaces[iface] = {}
                vals = stripped.split()
                interfaces[iface][vals[0]] = ''.join(vals[1:])
                if 'rate ' in stripped and (' slow' in stripped or ' 0'
                                            in stripped):
                    if 'bond-lacp-rate' not in features:
                        features['bond-lacp-rate'] = {}
                        features['bond-lacp-rate']['slow'] = []
                    features['bond-lacp-rate']['slow'].append(iface)
                else:
                    if (' no' not in stripped and ' 0' not in stripped and
                            'bypass-allow ' in stripped):
                        if 'bond-lacp-bypass-allow' not in features:
                            features['bond-lacp-bypass-allow'] = []
                        features['bond-lacp-bypass-allow'].append(iface)

            # Discover balance-xor bonds.
            if stripped.startswith('bond-mode balance-xor'):
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['bond-mode'] = 'balance-xor'
                if 'balance-xor' not in features:
                    features['balance-xor bonds'] = []
                features['balance-xor bonds'].append(iface)

            # Discover tunnels.
            if 'ip tunnel add' in stripped:
                if iface not in interfaces:
                    interfaces[iface] = {}
                if 'mode gre' in stripped:
                    interfaces[iface]['is-gre-tunnel'] = True
                    if 'IPGRE' not in features:
                        features['IPGRE'] = []
                    features['IPGRE'].append(iface)

            # Discover mtu is manually set.
            if stripped.startswith('mtu '):
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['mtu'] = stripped.split()[1].strip()

            # Discover vlan-protocol.
            if stripped.startswith('vlan') and 'protocol' in stripped:
                if iface not in interfaces:
                    interfaces[iface] = {}
                interfaces[iface]['vlan-protocol'] = (
                    stripped.split()[1].strip().lower())
            # If 'result' is > 0, that means we have discovered
            # one or more VLANs configured on an interface and
            # should populate that in the dict.
            if 'result' in locals() and len(result) > 0:
                if iface not in interfaces:
                    interfaces[iface] = {}
                # If 'parent' is > 0,  it indicates that this is a
                # sub-interface.  We add the interface and its
                # parent to the dict and also add the interface to
                # the subinterfaces dict.
                if 'parent' in locals() and len(parent) > 0:
                    interfaces[iface]['parent'] = parent
                    if iface not in subinterfaces:
                        subinterfaces[iface] = True
                # Finally, we add the discovered VLANs on the
                # interface to the dict.
                if 'vlans' not in interfaces[iface]:
                    interfaces[iface]['vlans'] = []
                interfaces[iface]['vlans'].extend(result)
                # And the same for inner_tage for Q-in-Q:
                if 'inner_tag' in locals() and len(inner_tag) > 0:
                    interfaces[iface]['parent'] = '{}.{}'.format(parent,
                                                                 result[0])
                    if 'inner_tag' not in interfaces[iface]:
                        interfaces[iface]['inner_tag'] = []
                        interfaces[iface]['inner_tag'] = inner_tag
                    if 'q-in-q' not in features:
                        features['q-in-q'] = []
                    features['q-in-q'].append(iface)
                # We clear out the 'result' list here because we
                # have already added the thus-far discovered VLANs
                # to the dict but may discover others under a
                # different "bridge-" keyword in the interface
                # config.
                result = []

            # If we have discovered bridgeports on an interface, it
            # is obviously a bridge.  We need tag the interface as
            # a bridge in the dict, add its members to the dict and
            # also add it to the bridges dict
            if 'bridgeports' in locals() and len(bridgeports) > 0:
                if iface not in interfaces:
                    interfaces[iface] = {}
                if iface not in bridges:
                    bridges[iface] = bridgeports
                interfaces[iface]['bridge-ports'] = bridgeports
                interfaces[iface]['is-bridge'] = True

            # If we found a bridge-ageing line, we need to populate
            # the 'bridge-ageing' field for this interface.
            if 'bridge_ageing' in locals() and len(bridge_ageing) > 0:
                if iface not in interfaces:
                    interfaces[iface] = {}
                if iface not in bridges:
                    bridges[iface] = True
                interfaces[iface]['bridge-ageing'] = bridge_ageing
                interfaces[iface]['is-bridge'] = True
                bridge_ageing = ''

            # If we have discovered bondslaves on an interface, it
            # is obviously a bond.  We need tag the interface as
            # a bond in the dict, add its slaves to the dict and
            # also add it to the bonds dict
            if 'bondslaves' in locals() and len(bondslaves) > 0:
                if iface not in interfaces:
                    interfaces[iface] = {}
                if iface not in bonds:
                    bonds[iface] = bondslaves
                interfaces[iface]['bond-slaves'] = bondslaves
                interfaces[iface]['is-bond'] = True
    fh.close()

    # Now that we've gone through all of the interfaces, its time to
    # set bond-lacp-rate fast on any bond that doesn't explicitly have it
    # set to slow and is also not using balance-xor.  We also add any bond
    # not listed in 'balance-xor bonds' to list '802.3ad bonds'.
    for iface in bonds:
        if ('bond-lacp-rate' not in interfaces[iface] and 'bond-mode' not in
                interfaces[iface]):
            interfaces[iface]['bond-lacp-rate'] = 'fast'
            if 'bond-lacp-rate' not in features:
                features['bond-lacp-rate'] = {}
            if 'fast' not in features['bond-lacp-rate']:
                features['bond-lacp-rate']['fast'] = []
            features['bond-lacp-rate']['fast'].append(iface)
        if 'bond-mode' not in interfaces[iface]:
            interfaces[iface]['bond-mode'] = '802.3ad'
            if '802.3ad bonds' not in features:
                features['802.3ad bonds'] = []
            features['802.3ad bonds'].append(iface)
        # Catch instances where they used '1' instead of 'fast'
        if ('bond-mode' not in interfaces[iface] or 'bond-lacp-rate' in
                interfaces[iface]):
            if '1' in interfaces[iface]['bond-lacp-rate']:
                interfaces[iface]['bond-lacp-rate'] = 'fast'
                if 'bond-lacp-rate' not in features:
                    features['bond-lacp-rate'] = {}
                if 'fast' not in features['bond-lacp-rate']:
                    features['bond-lacp-rate']['fast'] = []
                features['bond-lacp-rate']['fast'].append(iface)

    missing = []
    for iface in interfaces:
        # find missing parents.
        if ('parent' in interfaces[iface] and 'inner_tag' in interfaces[iface]
                and interfaces[iface]['parent'] not in interfaces):
            logger.debug(interfaces[iface])
            missing.append(interfaces[iface]['parent'])
        # mark vlan-protocol if it isn't already set.
        if ('parent' in interfaces[iface] and
                'inner_tag' not in interfaces[iface] and
                'vlan-protocol' not in interfaces[iface]):
            interfaces[iface]['vlan-protocol'] = '802.1q'
    # Create parents for orhpan sub-interfaces:
    for iface in missing:
        if iface not in interfaces:
            interfaces[iface] = {}
            interfaces[iface]['auto-created'] = True
            interfaces[iface]['vlan-protocol'] = '802.1q'
            interfaces[iface]['orphans'] = []
            interfaces[iface]['parent'] = iface.split('.')[0]
            for iface2 in interfaces:
                if ('parent' in interfaces[iface2] and
                        interfaces[iface2]['parent'] == iface):
                    interfaces[iface]['orphans'].append(iface2)

    satisfied.append(name)
    return (satisfied, bridges, bonds, features, interfaces, problems,
            subinterfaces, svis, vlans_inuse)


def discover_kernel(deprecated, satisfied, CL, discovered):  # noqa
    # Read in /proc/version to get kernel version information.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = CL + '/proc/version'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered)

    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Check for forwarding being disabled.
            if 'Linux version' in stripped:
                discovered['kernel'] = stripped
                discovered['kernel date'] = str(
                    "".join(map(str, stripped.split('(')[-1:]))).split(')')[0]
    fh.close()
    # If we couldn't discover this information, we don't want to satisfy the
    # dep for things that use it.
    if 'kernel' not in discovered:
        return (satisfied, discovered)

    satisfied.append(name)
    return (satisfied, discovered)


def discover_l3_defip(deprecated, satisfied, discovered, support_path):
    """
    Discover l3.defip.show.

    #
    # #     VRF     Net addr             Next Hop Mac        INTF MODID PORT PRIO CLASS HIT VLAN #noqa
    # 704   13       10.37.146.81/32      00:00:00:00:00:00 457630    0     0     0    0 n #noqa
    # Becomes...
    # "l3.defip": {
    #           "13": {
    #               "10.37.146.81/32": "457630",
    #               },
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'l3.defip.show'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)

    # Dict to hold l3.defip.show data
    discovered['l3.defip'] = {}

    logger.debug('Parsing: {}'.format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()

            # Look for route entries.
            # #     VRF     Net addr             Next Hop Mac        INTF MODID PORT PRIO CLASS HIT VLAN #noqa
            # 736   13       10.37.146.81/32      00:00:00:00:00:00 457557    0     0     0    0 y # noqa
            m = False
            m = re.search('\d+\s+(?P<vrf>\d+)\s+'  # noqa
                          '(?P<prefix>\d+.\d+.\d+.\d+\/\d+).+\d+:\d+\s+'  # noqa
                          '(?P<intf>4\d+)\s+',  # noqa
                          stripped)
            if m:
                vrf = m.group('vrf')
                prefix = m.group('prefix')
                intf = m.group('intf')
                if vrf not in discovered['l3.defip']:
                    discovered['l3.defip'][vrf] = {}
                if prefix not in discovered['l3.defip'][vrf]:
                    discovered['l3.defip'][vrf][prefix] = intf
    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_l3_egress(deprecated, satisfied, discovered, support_path):
    """
    Discover l3.egress.show.

    #
    # Entry  Mac                 Vlan INTF PORT MOD MPLS_LABEL ToCpu Drop RefCount L3MC #noqa
    # 457630  44:38:39:ff:00:18    0 14419   204    0        -1   no   no   33   no #noqa
    # Becomes...
    # "l3.egress": {
    #           "457630": {
    #                     "port": 204,
    #                     "gport": "0x800000cc"
    #                     },
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'l3.egress.show'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)

    # Dict to hold l3.egress.show data
    discovered['l3.egress'] = {}

    logger.debug('Parsing: {}'.format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()

            # Look for egress entries.
            # Entry  Mac                 Vlan INTF PORT MOD MPLS_LABEL ToCpu Drop RefCount L3MC #noqa
            # 457630  44:38:39:ff:00:18    0 14419   204    0        -1   no   no   33   no #noqa
            m = False
            m = re.search('(?P<entry>\d+)\s+\S+:\S+:\S+:\S+\s+\d+\s+\d+\s+'  # noqa
                          '(?P<port>\d+)', stripped)  # noqa
            if m:
                entry = m.group('entry')
                port = int(m.group('port'))
                gport = hex(port + 2147483648)
                if entry not in discovered['l3.egress']:
                    discovered['l3.egress'][entry] = {}
                    discovered['l3.egress'][entry]['port'] = port
                    discovered['l3.egress'][entry]['gport'] = gport

    fh.close()

    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_lldpctl(deprecated, satisfied, lldp, support_path): # noqa
    """Iterate through lldpctl to discover lldp neighbor information."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, lldp)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, lldp)
    filename = support_path + 'lldpctl'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, lldp)
    logger.debug("Parsing {}".format(filename))
    # Fields we are interested in...
    fields1 = ['ChassisID', 'SysName', 'SysDescr', 'PortDescr', 'PortID']
    fields2 = ['MgmtIP', 'Capability']
    # We need to be in a section to know our iface name.
    section = False
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith('-'):
                section = False
            if stripped.startswith('Interface:'):
                section = True
                vals = stripped.split()
                iface = vals[1].split(',')[0]
                logger.debug('Found section [{}]'.format(iface))
                if iface not in lldp:
                    lldp[iface] = {}
                lldp[iface]['Time'] = ' '.join(vals[7:])
            if section:
                for field in fields1:
                    if stripped.startswith(field):
                        logger.debug('Found field [{}].'.format(field))
                        lldp[iface][field] = ' '.join(stripped.split()[1:])
                for field in fields2:
                    if stripped.startswith(field):
                        logger.debug('Found field [{}].'.format(field))
                        if field not in lldp[iface]:
                            lldp[iface][field] = []
                        (lldp[iface][field].append(
                            ' '.join(stripped.split()[1:])))
    fh.close()
    satisfied.append(name)
    return (satisfied, lldp)


def discover_onie(deprecated, satisfied, discovered, support_path):  # noqa
    """Discover ONIE version."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'onie-version'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered)

    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Check for forwarding being disabled.
            if 'ONIE' in stripped:
                try:
                    field = stripped.split(':')[0].strip().split()[1]
                    if 'ONIE' not in discovered:
                        discovered['ONIE'] = {}
                    discovered['ONIE'][field] = stripped.split(field)[-1:]
                except IndexError:
                    logger.debug("Can't Discover ONIE from onie-version")
    fh.close()
    # If we couldn't discover this information, we don't want to satisfy the
    # dep for things that use it.
    if 'ONIE' not in discovered:
        return (satisfied, discovered)

    satisfied.append(name)
    return (satisfied, discovered)


def discover_ospf_interface(deprecated, satisfied, support_path, features):
    """
    Detect OSPF unnumbered interfaces.

    # Iterate through ospf.interface to detect interfaces configured for
    # OSPF Unnumbered.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    filename = support_path + "ospf.interface"
    if 'ospf-v2' in features:
        logger.debug("Parsing {}".format(filename))
        if os.path.isfile(filename):
            with open(filename, encoding='ISO-8859-1') as fh:
                for line in fh:
                    stripped = line.strip()
                    if not line.startswith(" ") and ' is ' in line:
                        iface = stripped.split()[0]
                    if 'UNNUMBERED' in stripped and '-v0' not in iface:
                        if 'ospf unnumbered' not in features:
                            features['ospf unnumbered'] = []
                        if iface not in features['ospf unnumbered']:
                            features['ospf unnumbered'].append(iface)
            fh.close()
            satisfied.append(name)
            return (satisfied, features)
        else:
            logger.debug("Could not open {}".format(filename))
            return (satisfied, features)
    else:
        logger.debug("OSPF-v2 is not configured.")
    satisfied.append(name)
    return (satisfied, features)


def discover_platform(deprecated, satisfied, discovered, support_path):
    """Parse platform.detect if it is available in the cl-support."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'platform.detect'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    # Open and parse platform.detect.
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if ',' in stripped:
                discovered['platform.detect'] = (str(stripped))
                satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_platform_detail(deprecated, satisfied, discovered, includes, # noqa
                             problems):
    """
    Look up our platform details in the platform_db.

    Whoever licked this function last owns it!  It is very complex and
    very easy to break.  You've been warned!!!
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered, problems)
    reqs = ['find_support_path', 'discover_platform']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, problems)
    if 'sysinfo' not in discovered:
        return (satisfied, discovered, problems)
    # We need to read in out platform database JSON files. This is the list
    # of vendors for which we should have a JSON file.
    db = {}
    filename = includes + "/platform_db/platform_db.json"
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        problems.append('* * * TE CONFIG ERROR * * * Could not find {}! '
                        'Please verify that Turbo-Entabulator '
                        'is installed properly.'.format(filename))
        return (satisfied, discovered, problems)
    logger.debug('Reading in {}...'.format(filename))
    with open(filename) as fh:
        db = json.load(fh)
    fh.close()

    # Create a mini DB that only contains our platform.
    platform_detect = discovered['platform.detect']
    platforms = {}
    platforms[platform_detect] = []
    logger.debug('Creating mini DB with only {}.'.format(platform_detect))
    for index in db['results']:
        if (index['device']['platform_detect'].upper() ==
                platform_detect.upper()):
            platforms[platform_detect].append(index)

    vendors = []
    models = []
    found = False
    logger.debug('Looking for {}...'.format(platform_detect))
    if len(platforms[platform_detect]) > 0:
        logger.debug('Found {} in platforms...'.format(
            discovered['platform.detect']))
        for index in platforms[platform_detect]:
            if 'Manufacturer' in discovered['sysinfo']:
                logger.debug('Comparing {} to {}'
                             .format(index['vendor']['name'],
                                     discovered['sysinfo']['Manufacturer']))
                if ('Vendor Name' in discovered and
                        discovered['Vendor Name'].upper() in
                        index['vendor']['name'].upper()):
                    discovered['platform'] = index
                    found = True
                    logger.debug('Vendor Match: Found {} as {}'
                                 .format(discovered['Vendor Name'],
                                         index['vendor']['name']))
                    break
                if (index['vendor']['name'].upper() in
                        discovered['sysinfo']['Manufacturer'].upper()):
                    discovered['platform'] = index
                    found = True
                    logger.debug('Manufacturer Match: Found {} as {}'
                                 .format(index['vendor']['name'],
                                         discovered['sysinfo']['Manufacturer']
                                         ))
                    break
                else:
                    vendors.append(index['vendor']['name'])
                    models.append(index['model'])
            else:
                vendors.append(index['vendor']['name'])
                models.append(index['model'])
        # If we couldn't narrow it down to one, combine the details.
        if len(vendors) == 1 and not found:
            discovered['platform'] = index
            found = True

        if len(vendors) > 0 and not found:
            # We don't know which one it really is so, we use the 'details'
            # of the last one in the index.
            discovered['platform'] = index
            # And we list possible vendors / models.
            discovered['platform']['vendor']['name'] = ('Possible vendor(s): '
                                                        + ', '.join(vendors))
            discovered['platform']['model'] = ('Possible model(s): '
                                               + ', '.join(models))
        # And now, we also put these in the raw discovered section.

        discovered['chipset'] = (index['device']['soc']['vendor'] + ' ' +
                                 index['device']['soc']['model'] + ' ' +
                                 index['device']['soc']['model_id'])
        discovered['vendor'] = discovered['platform']['vendor']['name']
        discovered['ports'] = ', '.join(index['device']['ports']['interfaces'])
        discovered['capabilities'] = (', '
                                      .join(index['device']['ports']
                                            ['capability']))
        discovered['model'] = discovered['platform']['model']
        if ('caveats' in discovered['platform']['device'] and
                discovered['platform']['device']['caveats']):
            discovered['caveats'] = discovered['platform']['device']['caveats']
        if len(discovered['platform']['datasheet']) > 0:
            discovered['datasheet'] = discovered['platform']['datasheet']

    else:
        discovered['model'] = (platform_detect +
                               ' not found in platform DB!')
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered, problems)


def discover_portmap(deprecated, satisfied, portmap, support_path):
    """Iterate through portmap to get swp to sdk_intf mapping."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, portmap)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, portmap)
    filename = support_path + 'portmap'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, portmap)
    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith('swp'):
                vals = stripped.split()
                portmap[vals[1]] = vals[0]
    fh.close()
    satisfied.append(name)
    return (satisfied, portmap)


def discover_ports_conf(deprecated, satisfied, CL, discovered, features):
    """Iterate through portmap to get swp to sdk_intf mapping."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered, features)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, features)
    filename = CL + '/etc/cumulus/ports.conf'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered, features)
    discovered['ports_conf'] = {}
    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith('#') and '=' in stripped:
                vals = stripped.split('=')
                discovered['ports_conf'][vals[0]] = vals[1]
                if vals[1] == 'loopback':
                    if 'hyperloop-ports' not in features:
                        features['hyperloop-ports'] = []
                    features['hyperloop-ports'].append(vals[0])
                if vals[1] == 'disabled':
                    if 'disabled-ports' not in features:
                        features['disabled-ports'] = []
                    features['disabled-ports'].append(vals[0])
    fh.close()
    satisfied.append(name)
    return (satisfied, discovered, features)

def discover_remote_syslog(deprecated, satisfied, discovered, CL):
    """Parse remote syslog server if it is available in the cl-support."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['CL', 'find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, features)

    path = CL + "/etc/rsyslog.d"
    logger.debug("debugging Remote syslog server")
    server=1
    server_dict = {}
    #loop through all rsyslogd config files, and check for "@" or "@@" configured,
    #which indicates UDP/TCP rsyslog server configuration. Put the detected server
    #IP/protocol into "discovered" dict for later use.
    for filename in os.listdir(path):
        if filename.endswith(".conf"):
            full_filename = path + "/" + filename
            with open(full_filename, encoding='ISO-8859-1') as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped.startswith('#'):
                        if "@@" in stripped:
                            server_dict['server'+str(server)] = {}
                            server_dict['server'+str(server)]['protocol'] = "tcp"
                            server_dict['server'+str(server)]['ip'] = re.findall( r'[0-9]+(?:\.[0-9]+){3}', stripped )
                            msg = ("Remote syslog server using TCP with IP address: {}".format(re.findall( r'[0-9]+(?:\.[0-9]+){3}', stripped )))
                            logger.debug(msg)
                            server += 1
                        elif "@" in stripped:
                            server_dict['server'+str(server)] = {}
                            server_dict['server'+str(server)]['protocol'] = "udp"
                            server_dict['server'+str(server)]['ip'] = re.findall( r'[0-9]+(?:\.[0-9]+){3}', stripped )
                            server += 1
            fh.close()
        else:
            continue

    if bool(server_dict):
      if 'remote_syslog' not in discovered:
        discovered['remote_syslog'] = server_dict

    for key,val in discovered['remote_syslog'].items():
        msg = ("Remote syslog server:{} - {}".format(key,val))
        logger.debug(msg)

    satisfied.append(name)
    return (satisfied, discovered)


def discover_services(deprecated, satisfied, support_path):  # noqa
    """
    Figure out which services are configured and their status.

    # Discover which services are configured and which VRF they're configured
    # to run in.  This can probably use some augentation.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, None)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, None)
    # Specify the files we're going to iterate through.
    systemd_files = ['systemd.unitfiles', 'systemd.units', 'systemd.failed']
    # Speficy the services we're interested in.
    svc = ['!clagd', 'dhcpd', 'dhcpd6', 'dhcrelay', 'dhcrelay6', '!frr',
           'hsflowd', '!ledmgrd', '!lldpd', '!netd', 'netq-agent', 'netqd',
           'ntp', '!ptmd', '!pwmpd', 'rdnbrd', 'snmpd', 'snmptrapd', 'sshd',
           '!switchd', '!sx_sdk', 'vxsnd', 'vxrd']
    enabled = []
    services = {}
    for file in systemd_files:
        filename = support_path + file
        if not os.path.isfile(filename):
            logger.debug("ERROR: Could not open {}.".format(filename))
            # return(satisfied, False)
            # We're going to continue instead of failing the module.
            continue
        logger.debug("Parsing {}".format(filename))
        with open(filename, encoding='ISO-8859-1') as fh:
            for line in fh:
                stripped = line.strip()
                for item in svc:
                    if 'systemd.unitfiles' in filename:
                        interested = item + ".service"
                        interested2 = item + "@.service"
                        if ((interested in stripped
                             or interested2 in stripped)
                                and '' in stripped):
                            s, _ = stripped.split(".")
                            enabled.append(s)
                    if 'systemd.units' in filename:
                        if (stripped.startswith(item) and
                                'active' in stripped and item in enabled):
                            s = stripped.split()
                            s1 = s[0]
                            actual, _ = s1.split(".")
                            if '@' in actual:
                                s2, vrf = actual.split('@')
                            else:
                                s2 = actual
                                vrf = "default"
                            if s2 not in services:
                                services[s2] = {}
                                services[s2]['vrf'] = []
                            if vrf not in services[s2]['vrf']:
                                services[s2]['vrf'].append(vrf)
                    if 'systemd.failed' in filename:
                        if not stripped.find('\xe2\x97\x8f'):
                            if 'FAILED-SERVICES' not in services:
                                services['FAILED-SERVICES'] = {}
                            fs = stripped.split()
                            if fs[1] not in services['FAILED-SERVICES']:
                                services['FAILED-SERVICES'][fs[1]] = []
                                (services['FAILED-SERVICES'][fs[1]].append(
                                    'Description: {}'
                                    .format(' '.join(fs[5:]))))
                                (services['FAILED-SERVICES'][fs[1]].append(
                                    '       LOAD: {}'.format(fs[2])))
                                (services['FAILED-SERVICES'][fs[1]].append(
                                    '     ACTIVE: {}'.format(fs[3])))
                                (services['FAILED-SERVICES'][fs[1]].append(
                                    '        SUB: {}'.format(fs[4])))
                                # Even though the service is failed, it is
                                # enabled so, we need to add it to the services
                                # list.
                                v1 = fs[1].replace('.service', '').split('@')
                                if len(v1) < 3:
                                    v1.append('default')
                                if not v1[0] in services:
                                    services[v1[0]] = {}
                                    services[v1[0]]['vrf'] = []
                                if not v1[1] in services[v1[0]]['vrf']:
                                    services[v1[0]]['vrf'].append(v1[1])
        fh.close()
    satisfied.append(name)
    return (satisfied, services)


def discover_smart(deprecated, satisfied, discovered, support_path):
    """Iterate through smart to discover disk params."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'smart'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered)
    logger.debug("Parsing {}".format(filename))
    # Fields we are interested in...
    fields = ['Device Model', 'Serial Number', 'LU WWN Device Id',
              'Firmware Version', 'User Capacity', 'Sector Size',
              'Rotation Rate', 'Form Factor']
    discovered['smart'] = {}
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            for field in fields:
                if stripped.startswith(field):
                    field1 = field.split(':')[0]
                    logger.debug('Found field [{}].'.format(field1))
                    discovered['smart'][field1] = ' '.join(stripped.split(
                        field + ':')[1:]).strip()
    fh.close()
    satisfied.append(name)
    return (satisfied, discovered)


def discover_smonctl(deprecated, satisfied, support_path):  # noqa
    """parse data from smonctl."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, {})
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, {})
    filename = support_path + 'smonctl'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, {})
    smonctl = {}
    logger.debug("Parsing {}".format(filename))

    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if len(stripped) < 3 or stripped.startswith('#'):
                continue
            if stripped.startswith('Unhandled Exception'):
                msg = 'smonctl had Unhandled Exception. No usable data.'
                logger.debug(msg)
                smonctl['ERROR'] = msg
                fh.close()
                satisfied.append(name)
                return (satisfied, smonctl)
            if "Messages:" in stripped:
                messages = True
                smonctl['Messages'] = []
                continue
            if 'messages' in locals():
                smonctl['Messages'].append(stripped)
            if stripped[:1].isupper():
                vals = stripped.split(':')
                key = vals[0].replace(':', '')
                if key not in smonctl:
                    smonctl[key] = []
                    smonctl[key].append([x.strip() for x in vals[1:]])
                else:
                    smonctl[key].append(stripped)

    fh.close()
    logger.debug(smonctl)
    satisfied.append(name)
    return (satisfied, smonctl)


def discover_stp(deprecated, satisfied, features, interfaces, support_path):
    """Discover STP state from mstp.show output."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features, interfaces)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features, interfaces)

    filename = support_path + 'mstp.show'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, features, interfaces)
    logger.debug("Parsing {}".format(filename))

    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # if the line is a comment, we don't care about it!
            if not stripped.startswith('#'):
                if ('CIST info' in stripped and ':' in stripped):
                    vals = stripped.split()
                    iface = vals[0].split(':')[1]
                if ('port id' in stripped and 'state' in stripped):
                    vals = stripped.split()
                    stp_state = vals[4]
                    logger.debug('{}: {}'.format(iface, stp_state))
                    if iface not in interfaces:
                        interfaces[iface] = {}
                    interfaces[iface]['stp state'] = stp_state
                    if 'stp' not in features:
                        features['stp'] = {}
                    features['stp'][iface] = stp_state
    fh.close()
    satisfied.append(name)
    return (satisfied, features, interfaces)


def discover_switchd_conf(deprecated, satisfied, CL, discovered):
    """
    Parse switchd.conf to determine the Reserved Vlan Range.

    This will need to be revisited now that the latest 4.x is changing
    the default range.
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered, None)
    reqs = ['CL', 'find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered, None)
    filename = CL + '/etc/cumulus/switchd.conf'
    logger.debug("Parsing {}".format(filename))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, discovered, None)
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # If the customer has explicitly specified the Reserved VLAN
            # Range, we will collect Low and High limits of the range.
            if stripped.startswith("resv_vlan_range"):
                configured = stripped.split("=")
                rvr = configured[1].split("-")
                rvr = map(int, rvr)
                rvr = list(rvr)
                logger.debug("Found resv_vlan_range: {} - {}"
                             .format(rvr[0], rvr[1]))
            # Look for vrf_route_leak_enable
            if (stripped.startswith('vrf_route_leak_enable') and 'dynamic' not
                    in stripped):
                discovered['vrf_route_leak_enable'] = (
                    stripped.split('=')[-1].strip())
            # Look for dynamic route leaking.
            if stripped.startswith('vrf_route_leak_enable_dynamic'):
                discovered['vrf_route_leak_enable_dynamic'] = (
                    stripped.split('=')[-1].strip())
            # Look for atomic or non-atomic
            if stripped.startswith('acl.non_atomic_update_mode'):
                discovered['acl.non_atomic_update_mode'] = (
                    stripped.split('=')[-1].strip())

    fh.close()
    # If we were unable to discover the Reserved Vlan Range in switchd.conf,
    # We can assume that it is the default (3000 - 3999).
    if 'rvr' not in locals():
        rvr = [3000, 3999]
        logger.debug("No explicitly configured reserved VLAN range found.")
        logger.debug("Defaulting to 3000 - 3999")
    discovered['resv_vlan_range'] = (
        "[{} - {}]".format(rvr[0], rvr[1]))
    satisfied.append(name)
    return (satisfied, discovered, rvr)


def discover_sysctl(deprecated, satisfied, support_path, forwarding, timers): # noqa
    """
    Iterate through sysctl to detect if forwarding is disabled for v4 or v6.

    # This may or may not indicate a misconfiguration on the switch.
    # adding detection of ARP timeout value from
    # "net.ipv4.neigh.default.base_reachable_time_ms" in sysctl
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, forwarding, timers)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, forwarding, timers)
    filename = support_path + 'sysctl'
    logger.debug("support file path is {}".format(support_path))
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, forwarding, timers)
    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Check for forwarding being disabled.
            if stripped.startswith("net.ipv4.conf.all.forwarding = 0"):
                if 'sysctl' not in forwarding:
                    forwarding['sysctl'] = {}
                forwarding['sysctl']['net.ipv4.conf.all.forwarding'] = (
                    'Disabled')
            if stripped.startswith("net.ipv6.conf.all.forwarding = 0"):
                if 'sysctl' not in forwarding:
                    forwarding['sysctl'] = {}
                forwarding['sysctl']['net.ipv6.conf.all.forwarding'] = (
                    'Disabled')

            if stripped.startswith(
                    "net.ipv4.neigh.default.base_reachable_time_ms"):
                arp = stripped.split("=")
                if 'sysctl' not in timers:
                    timers['sysctl'] = {}
                (timers['sysctl']
                    ['net.ipv4.neigh.default.base_reachable_time_ms']) = (
                        int(arp[-1]))
    fh.close()
    satisfied.append(name)
    return (satisfied, forwarding, timers)


def discover_syseeprom(deprecated, satisfied, support_path, discovered): # noqa
    """Discover decode-syseeprom."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['discover_etc']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)

    filename = support_path + 'decode-syseeprom'
    if os.path.isfile(filename):
        logger.debug("Parsing {}".format(filename))
        with open(filename, encoding='ISO-8859-1') as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith('Product Name '):
                    ds_pn = stripped.split()[4].strip()
                    discovered['Product Name'] = ds_pn
                    logger.debug("Detected: {}".format(ds_pn))
                # Since we're already here, detect the device Version
                # so we can see if this is a Spectrum A0 ASIC.
                if stripped.startswith('Device Version'):
                    asic_version = stripped.split()[4]
                    discovered['Spectrum ASIC Version'] = asic_version
                # Detect CX devices:
                if stripped.startswith('Vendor Name'):
                    vendor_name = stripped.split()[4]
                    discovered['Vendor Name'] = vendor_name
                    if 'Cumulus Networks' in stripped:
                        discovered['CX'] = True
                # Detect Service Tags
                if stripped.startswith('Service Tag'):
                    vals = stripped.split()
                    if len(vals) > 3:
                        discovered['service_tag'] = vals[4].strip()
                # Detect ONIE Version.
                if stripped.startswith('ONIE Version'):
                    onie_version = stripped.split()[-1]
                    discovered['onie_version'] = onie_version

        fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_traffic_conf(deprecated, satisfied, CL, features):
    """Discover various info in traffic.conf."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['CL']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    # Discovery or Detection code goes here...
    filename = CL + '/etc/cumulus/datapath/traffic.conf'
    if not os.path.isfile(filename):
        logger.debug("Could not open {}".format(filename))
        return (satisfied, features)
    logger.debug("Parsing {}".format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if stripped.startswith('link_pause.') and 'port_set' in stripped:
                ports = stripped.split('=')[-1].strip()
                group = stripped.split('.')[1]
                if 'link_pause' not in features:
                    features['link_pause'] = {}
                if group not in features['link_pause']:
                    features['link_pause'][group] = []
                features['link_pause'][group].append(ports)
    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, features)


def discover_uptime(deprecated, satisfied, discovered, support_path):
    """Parse uptime if it is available in the cl-support."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'uptime'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    discovered['uptime'] = {}
    # Open and parse uptime.
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if 'load average' in stripped:
                discovered['uptime'] = (str(stripped))
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_v4_routes(deprecated, satisfied, support_path): # noqa
    """Discover ipv4 routes from ip.route and populate dict vr_routes."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, {})
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, {})
    filename = support_path + 'ip.route'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, {})

    # Create our empty dict to hold our lists of VRF routes.
    v4_routes = {}

    # Things we ignorw...
    ignore = ['#', 'local', 'broadcast', 'unreachable', 'anycast', 'fe', 'ff',
              '::']

    # Open and parse ip.route
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Skip lines we're not interested in...
            skip = False
            for item in ignore:
                if stripped.startswith(item):
                    skip = True
            if skip:
                continue

            # Look for a prefix...
            prefix = False
            if re.search("^\d+\.\d+\.\d+\.\d+", stripped):  # noqa
                prefix = stripped.split()[0]
                # Handle /32's
                if '/' not in prefix:
                    prefix = prefix + '/32'
            # Handle default routes
            if re.search("^default ", stripped):
                prefix = '0.0.0.0/0'

            # Since we blast prefix when we get a new line, we need to keep a
            # different copy of it for ECMP routes to know what prefix to
            # assign the nexthop interface to...
            if prefix:
                working = prefix
                # Do we see a table (VRF) in the line?
                # If not, its the default VRF.
                vrf = 'default'
                if 'table' in stripped:
                    vals1 = stripped.split('table ')[1].strip()
                    vrf = vals1.split()[0].strip()
                # Do we have a dict for this VRF in v4_routes?
                # If not, create it.
                if vrf not in v4_routes:
                    v4_routes[vrf] = {}

            # If we don't have a prefix, but we do have a dev, we are going to
            # need to use our working prefix.
            if not prefix:
                prefix = working

            # Is this a new prefix?  If so, we need to add a list to contain
            # its nexthop devs in the appropriate VRF.
            if prefix not in v4_routes[vrf]:
                v4_routes[vrf][prefix] = {}

            # Do we see a dev
            m = False
            m = re.search(" dev (?P<match>\S+) ", stripped)  # noqa
            if m:
                # Does the dev that we found exist in the appropriate list?
                # If not, append it to the list.
                if m.group('match') not in v4_routes[vrf][prefix]:
                    n = False
                    n = re.search(" via (?P<match>\S+) ", stripped)  # noqa
                    if n:
                        v4_routes[vrf][prefix][m.group('match')] = (
                            n.group('match'))
                    else:
                        v4_routes[vrf][prefix][m.group('match')] = 'Connected'

    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, v4_routes)


def discover_vnis(deprecated, satisfied, support_path, discovered): # noqa
    """Discover VNIs and remote VTEPs."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    filename = support_path + 'evpn.vni.detail'
    logger.debug(filename)
    # Verify that we can even open the file.
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)
    # Time to parse the file...
    discovered['vnis'] = {}
    vtep_search = False
    # Open and parse ip.route
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            # Look for a VNI...
            if re.search("^VNI:", stripped):  # noqa
                vni = stripped.split()[1]
                if vni not in discovered['vnis']:
                    discovered['vnis'][vni] = {}
            if re.search("^Remote VTEPs", stripped):
                vtep_search = True
            if re.search("^Number of MACs", stripped):
                vtep_search = False
            if not vtep_search:
                continue
            if re.search("^\d+\.\d+\.\d+\.\d+", stripped):  # noqa
                vtep = stripped.split()[0]
                if 'remote vteps' not in discovered['vnis'][vni]:
                    discovered['vnis'][vni]['remote vteps'] = []
                if vtep not in discovered['vnis'][vni]['remote vteps']:
                    discovered['vnis'][vni]['remote vteps'].append(vtep)
    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_vxlan_info(deprecated, satisfied, discovered, support_path): # noqa
    """
    Discover gports and tunnels from switchd.debug.vxlan.info.

    #
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
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, discovered)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, discovered)
    # Verify that we can even open the file.
    filename = support_path + 'switchd.debug.vxlan.info'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, discovered)

    # Dicts to hold gport and tunnel data
    discovered['gports'] = {}
    discovered['tunnels'] = {}

    # A bool to control looking for second line of gport.
    gport2 = False

    logger.debug('Parsing: {}'.format(filename))
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()

            if stripped.startswith('gport:'):
                gport2 = False
            # Look for gports first line.
            # gport: 0x800000cc; vpn: (28673/0x7001); eg_if: 202304; f: 0x985 class_id: 2 # noqa
            m = False
            m = re.search('gport:\s+(?P<gport>0x\S{8}).+: 2$', stripped)  # noqa
            if m:
                gport = m.group('gport')
                gport2 = True
            # Lookk for gports second line.
            #  match_tun: 0x4c00000f; egress_tun: 0x4c00000d
            if gport2:
                m = False
                m = re.search('match_tun:\s(?P<match_tun>.+);.egress_tun:.'  # noqa
                              '(?P<egress_tun>.+)$', stripped)
                if m:
                    if gport not in discovered['gports']:
                        discovered['gports'][gport] = {}
                        match_tun = m.group('match_tun')
                        egress_tun = m.group('egress_tun')
                        discovered['gports'][gport]['match_tun'] = match_tun
                        discovered['gports'][gport]['egress_tun'] = egress_tun
                    gport2 = False
            # Look for tunnels.
            # init_id: 0x4c00000d; term_id: 0x4c00000f; sip: 10.37.254.34; dip: 10.37.254.48 # noqa
            m = False
            m = re.search('init_id:\s+(?P<init_id>\S{10});\s+term_id:\s+'  # noqa
                          '(?P<term_id>\S{10});\s+sip:\s+'
                          '(?P<sip>\d+\.\d+\.\d+\.\d+);\s+dip:\s'
                          '(?P<dip>\d+\.\d+\.\d+\.\d+)$', stripped)
            if m:
                init_id = m.group('init_id')
                term_id = m.group('term_id')
                sip = m.group('sip')
                dip = m.group('dip')
                # Not sure if there is a unique index on tunnels so we will
                # create one by combining init_id and term_id since that is the
                # match we will be looking for anyway to check that the sip
                # matches the kernel programmed nexthop.
                index = init_id + '_' + term_id
                if index not in discovered['tunnels']:
                    discovered['tunnels'][index] = {}
                    discovered['tunnels'][index]['init_id'] = init_id
                    discovered['tunnels'][index]['term_id'] = term_id
                    discovered['tunnels'][index]['sip'] = sip
                    discovered['tunnels'][index]['dip'] = dip
    fh.close()

    # This is just some debug code for devel:
    logger.debug('Total GPORTS: {} Total Tunnels: {}'
                 .format(len(discovered['gports']),
                         len(discovered['tunnels'])))

    satisfied.append(name)
    # Then, return:
    return (satisfied, discovered)


def discover_vxlan_type(deprecated, satisfied, features, interfaces): # noqa
    """Determine the type of VxLAN that is configured."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, features)
    reqs = ['discover_ifquery', 'discover_frr_bgp_ip']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, features)
    vxlan = False
    symmetric = False
    centralized = False
    configured = 0
    vnis = 0
    for iface in interfaces:
        if 'vxlan-id' in interfaces[iface]:
            vxlan = True
            configured += 1
            if 'vxlan' in features:
                if 'l3 vnis' in features['vxlan']:
                    for vni in features['vxlan']['l3 vnis']:
                        if vni == interfaces[iface]['vxlan-id']:
                            vnis += 1
                            symmetric = True
                if 'bgp' in features:
                    for vrf in features['bgp']:
                        if ('address-family' in features['bgp'][vrf]
                                and 'l2vpn evpn' in
                                features['bgp'][vrf]['address-family'] and
                                'advertise-default-gw' in
                                (features['bgp'][vrf]['address-family']
                                         ['l2vpn evpn'])):
                            centralized = True

    if vxlan:
        if symmetric:
            vxlan_type = "Symmetric"
        else:
            vxlan_type = "Asymmetric"
        if centralized:
            vxlan_type = "Centralized"
        if 'vxlan' not in features:
            features['vxlan'] = {}
        features['vxlan']['type'] = vxlan_type
        logger.debug("VxLAN Interfaces: {}".format(configured))
        logger.debug("   Matching VNIs: {}".format(vnis))
        logger.debug("      VxLan Type: {}".format(vxlan_type))

    satisfied.append(name)
    return (satisfied, features)


def discover_young_routes(deprecated, satisfied, support_path):  # noqa
    """Discover very young routes."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, [])
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, [])
    files = ['zebra.route', 'zebra.ipv6_route']
    young_routes = []
    # Minumum Age:
    min_age = 10
    for file in files:
        filename = support_path + file
        if os.path.isfile(filename):
            logger.debug("Parsing {}".format(filename))
            with open(filename, encoding='ISO-8859-1') as fh:
                for line in fh:
                    if '/' in line and ',' in line:
                        stripped = line.strip()
                        vals = stripped.split(',')
                        prefix = vals[0]
                        timestamp = vals[-1]
                        if ':' in timestamp:
                            ts = timestamp.split(':')
                            ts1 = ts[0] + ts[1] + ts[2]
                            age = int(ts1.strip())
                            if age <= min_age:
                                entry = prefix + ' -' + timestamp
                                young_routes.append(entry)
                            #    msg = ("YOUNG-ROUTE: '{}' is less than "
                            #           "{} mins old."
                            #           .format(entry, min_age))
                            #    logger.debug(msg)
            fh.close()
        else:
            logger.debug("ERROR: Could not open {}.".format(filename))
    satisfied.append(name)
    # Then, return:
    return (satisfied, young_routes)


def discover_zebra_intf(deprecated, satisfied, interfaces, support_path):
    """Parse zebra.intf to discover various information we're interested in."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, interfaces)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, interfaces)
    # zebra.intf has to be readable...
    filename = support_path + 'zebra.intf'
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        return (satisfied, interfaces)
    with open(filename, encoding='ISO-8859-1') as fh:
        for line in fh:
            stripped = line.strip()
            if (('line protocol' in stripped or
                 stripped.startswith('Interface')) and 'Type' not in stripped):
                vals = stripped.split()
                iface = vals[1]
                logger.debug('Parsing [{}]'.format(iface))
                if iface not in interfaces:
                    interfaces[iface] = {}
            if 'Link ups:' in stripped:
                logger.debug(stripped)
                vals = stripped.split(':')
                vals1 = stripped.split('last:')
                interfaces[iface]['link ups'] = vals[1].strip().split()[0]
                interfaces[iface]['last up'] = vals1[-1].strip()
            if 'Link downs:' in stripped:
                logger.debug(stripped)
                vals = stripped.split(':')
                vals1 = stripped.split('last:')
                interfaces[iface]['link downs'] = vals[1].strip().split()[0]
                interfaces[iface]['last down'] = vals1[-1].strip()
    fh.close()
    satisfied.append(name)
    # Then, return:
    return (satisfied, interfaces)
