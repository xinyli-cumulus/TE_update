#!/usr/bin/env python3
"""Turbo-Entabulator."""

# Copyright(c) 2018, 2019, 2020 Cumulus Networks, Inc
# John Fraizer <jfraizer@cumulusnetworks.com>

import os
import sys
from pprint import pformat
from turbo_entabulator.detections import (detect_3ie3_3me3_discard,
                                          detect_arp_mac_timers_mismatch,
                                          detect_bad_gport,
                                          # detect_bad_sysclock, # Disabled
                                          detect_broken_cl,
                                          detect_bcm_counters,
                                          detect_clagd_issues, detect_cm26383,
                                          detect_core_files,
                                          detect_dhcrelay_probs,
                                          detect_dependent_ports_intersect,
                                          detect_dup_ip_mac, detect_egp_to_igp,
                                          detect_failed_services,
                                          detect_forwarding_disabled,
                                          detect_frr_ip_config,
                                          detect_high_discards,
                                          detect_hsflow_unsupported,
                                          detect_link_flaps, detect_link_pause,
                                          detect_lnv_vxlan, detect_log_sigs,
                                          detect_tcp_rsyslog,
                                          detect_toomany_vlans,
                                          detect_missing_prefix_lists,
                                          detect_missing_route_maps,
                                          detect_mlx_smbios_error,
                                          detect_nondeterministic_routerid,
                                          detect_ospf_unnumbered_misconfig,
                                          detect_ports_conf,
                                          detect_redist_neigh_misconfig,
                                          detect_resv_vlan_misconfigs,
                                          detect_smonctl,
                                          detect_spectre_meltdown,
                                          detect_stp_discarding,
                                          detect_sub_int_bridge_vlan_collision,
                                          detect_subint_misconfigs,
                                          detect_sym_vxlan_on_spectrum_v0,
                                          detect_test_pkgs,
                                          detect_route_leak_misconfig,
                                          detect_unlicensed,
                                          detect_unsupported_protocols,
                                          detect_unsupported_vx_routing,
                                          detect_vxlan_bad_path,
                                          detect_wrong_onie_accton,
                                          detect_young_routes)
from turbo_entabulator.discovery import (discover_addresses,
                                         discover_bcm_counters,
                                         discover_bios, discover_bridges,
                                         discover_clagd, discover_cmdline,
                                         discover_control, discover_cpld,
                                         discover_date, discover_dhcrelay_conf,
                                         discover_dpkg, discover_dmidecode,
                                         discover_etc, discover_ethtool_stats,
                                         discover_eth0, discover_evpn_routes,
                                         discover_frr_bgp_ip,
                                         discover_frr_ospf, discover_ifquery,
                                         discover_kernel, discover_l3_defip,
                                         discover_l3_egress, discover_lldpctl,
                                         discover_onie,
                                         discover_ospf_interface,
                                         discover_platform,
                                         discover_platform_detail,
                                         discover_portmap, discover_ports_conf,
                                         discover_remote_syslog,
                                         discover_services, discover_smart,
                                         discover_smonctl, discover_stp,
                                         discover_switchd_conf,
                                         discover_sysctl, discover_syseeprom,
                                         discover_traffic_conf,
                                         discover_uptime, discover_v4_routes,
                                         discover_vnis, discover_vxlan_info,
                                         discover_vxlan_type,
                                         discover_young_routes,
                                         discover_zebra_intf)
from turbo_entabulator.utilities import (expand_frr_ec,
                                         find_frr_path,
                                         find_ifquery_path,
                                         find_support_path,
                                         test_check_dependencies,
                                         verify_path, wisdom)
import logging
from turbo_entabulator.m_logger import logger

# Jack up the recursion limit.  ZD 4851 cl_support_at4d-lf02_20010128_000948
# was breaking glob expansion of bridge-ports when it was set to the default
# of 1000.  You should see the bridge-ports line of iface bridge on that sw!
sys.setrecursionlimit(5000)

VERSION = 'Turbo Entabulator v0.7.31 - Mon April 7 20.10:00 EDT 2020'

MIN_VERSION_PY3 = (3, 4)  # min. 3.x version
if sys.version_info < MIN_VERSION_PY3:
    sys.exit(
        "ERROR: This script requires Python 3.x >= %s;"
        " you're running %s." % (
            '.'.join(map(str, MIN_VERSION_PY3)),
            '.'.join(map(str, sys.version_info))
            ))


"""
def example_function(deprecated, satisfied, <others>):
    # Example Format of discovery / detection functions.
    # All detection functions need to
    # follow this format and must include a description at the beginning of the
    # function describing the purpose of the function.  The boilerplate code
    # shown in this example must be included.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, others)
    reqs = ['list', 'of', 'prerequesite', 'functions']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, others)
    # Discovery or Detection code goes here...
    #
    # Any failure should return(satisfied) [and any other structures as
    # necessary].
    #
    # If the function completes safely, append the function name to list
    # satisfied:
    satisfied.append(name)
    # Then, return:
    return(satisfied, others)
"""


def defaults(args_dict):
    """
    Initialize the various things and set defaults if not overriden.

    + Log level
    + Determine base directory
    + Derive 'includes' directory from base if not specified.
    """
    # Set the log level in the logger
    if 'verbose' in args_dict and args_dict['verbose']:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

    # print dict of cli args
    logger.debug('Args passed to TE:\n{}'.format(pformat(args_dict)))

    # Determine the base directory this file is in.
    base_dir = os.path.dirname(__file__)
    logger.debug('base_dir = {}'.format(base_dir))

    # if the user does not specify an alternate platformdb json file, assume
    # the one in the package is to be used
    if ('includes' not in args_dict) or (not args_dict['includes']):
        args_dict['includes'] = os.path.join(base_dir, "includes")
    # verify and expand includes directory.
    args_dict['includes'] = verify_path(args_dict['includes'])
    logger.debug('Using JSON includes base: {}'
                 .format(args_dict['includes']))
    # Set up some sane defaults.
    if 'deprecated' not in args_dict:
        args_dict['deprecated'] = []
    # Set up the exclude list.
    if 'exclude' not in args_dict:
        args_dict['exclude'] = []
    # Set up our show list.
    if 'show' not in args_dict:
        args_dict['show'] = []

    # verify and expand cl_support path
    if 'cl_support' not in args_dict:
        logger.error("No cl_support path provided!")
    else:
        args_dict['cl_support'] = verify_path(args_dict['cl_support'])
    # If we made it this far, we can bless this input struct.
    args_dict['blessed'] = True

    logger.debug('Parsing {}'.format(args_dict['cl_support']))

    return(args_dict)


def zulu(args_dict):  # noqa
    """
    This is the main function that calls all other portions of this script.

    satisfied[] is a list of modules that have been successfully executed.
    "successfully executed" means that they were able to obtain the data that
    the module is expected to obtain.  Only if a module has successfully
    executed should that module be added to list satisfied.
    Example: satisfied.append('module_name')

    :param input:
    :return:
    """

    """Setup"""
    name = sys._getframe().f_code.co_name
    # Do we have a blessed input structure?
    if 'blessed' not in args_dict:
        logger.error('turbo_entabulator.zulu() is refusing to operate '
                     'on non-blessed input!')
        exit(code=1)

    logger.debug("This is {}().".format(name))
    logger.debug("Input Struct: {}".format(args_dict))

    # Set our CL variable to point to the cl_support directory.
    cl_support = args_dict['cl_support']
    # Set up our list of deprecated detections.
    deprecated = args_dict['deprecated']
    # Set up our show list.
    show = args_dict['show']

    # Set up our includes directory.
    includes = args_dict['includes']
    # Set up our various dicts and lists that are used throughout the script.
    # dicts
    bcm_counters = {}
    bonds = {}
    bridges = {}
    discovered = {}
    features = {}
    forwarding = {}
    high_discards = {}
    interfaces = {}
    lldp = {}
    portmap = {}
    svis = {}
    subinterfaces = {}
    timers = {}
    # lists
    info = []
    problems = []
    satisfied = []
    vlans_inuse = []
    warnings = []
    whitelisted = []

    # Populate some fields from info we have already:
    discovered['Script Version'] = VERSION
    if '/' in cl_support:
        if cl_support[-1] == '/':
            cl_support = cl_support[:-1]
        discovered['cl_support'] = cl_support.split("/")[-1]
    else:
        discovered['cl_support'] = cl_support

    # This is a list of all possible things we may want to output from our
    # dicts and lists:
    all_fields = ['addresses', 'bcm_counters', 'bonds', 'bridges',
                  'deprecated', 'discovered', 'features', 'forwarding',
                  'high_discards', 'info', 'input', 'interfaces', 'logs',
                  'lldp', 'portmap', 'regex_matches', 'satisfied', 'services',
                  'svis', 'suggestions', 'subinterfaces', 'timers', 'problems',
                  'smonctl', 'v4_routes', 'vlans_inuse', 'young_routes',
                  'warnings', 'whitelisted']

    """Discovery Functions"""
    # Test that our check_dependencies function is working as expected.
    satisfied = test_check_dependencies(deprecated, satisfied)
    # Find the support_path since it may be "support" or "Support".
    satisfied, support_path = find_support_path(deprecated, satisfied,
                                                cl_support)
    # Find the ?.show_running file we need to parse for FRR.
    satisfied, frr_path = find_frr_path(deprecated, satisfied, support_path)
    # Find the ifquery file we need to parse.
    satisfied, ifquery_path = find_ifquery_path(deprecated, satisfied,
                                                support_path)
    # Discover which services are running.
    satisfied, services = discover_services(deprecated, satisfied,
                                            support_path)
    # Parse various files in /etc.
    satisfied, discovered, features = discover_etc(deprecated, satisfied,
                                                   cl_support, discovered,
                                                   features, services)
    # Parse ip.link to get eth0 MAC.
    satisfied, discovered = discover_eth0(deprecated, satisfied, discovered,
                                          support_path)
    # Parse decode-syseeprom.
    satisfied, discovered = discover_syseeprom(deprecated, satisfied,
                                               support_path, discovered)
    #  Parse switchd.conf
    satisfied, discovered, rvr = discover_switchd_conf(deprecated, satisfied,
                                                       cl_support, discovered)
    # Parse sysctl.
    satisfied, forwarding, timers = discover_sysctl(deprecated, satisfied,
                                                    support_path, forwarding,
                                                    timers)
    # Parse ?.show_running for BGP features.
    satisfied, discovered, features, forwarding = discover_frr_bgp_ip(
        deprecated, satisfied, discovered,
        frr_path, features, forwarding)
    # Parse ?.show_running for OSPF features.
    satisfied, features = discover_frr_ospf(deprecated, satisfied, frr_path,
                                            features)
    # Parse ospf.interface.
    satisfied, features = discover_ospf_interface(deprecated, satisfied,
                                                  support_path, features)
    # Parse ifquery
    (satisfied, bridges, bonds, features, interfaces, problems,
     subinterfaces, svis, vlans_inuse) = (
        discover_ifquery(deprecated, satisfied, ifquery_path, bridges,
                         bonds, features, interfaces, problems,
                         subinterfaces, svis, vlans_inuse))
    # Discover VxLAN type.
    satisfied, features = discover_vxlan_type(deprecated, satisfied, features,
                                              interfaces)

    # Parse ethtool.stats
    satisfied, interfaces = discover_ethtool_stats(deprecated, satisfied,
                                                   interfaces, support_path)

    # Parse dmidecode to gather system information.
    satisfied, discovered = discover_dmidecode(deprecated, satisfied,
                                               discovered, support_path)
    # Parse uptime.
    satisfied, discovered = discover_uptime(deprecated, satisfied, discovered,
                                            support_path)
    # Parse portmap.
    satisfied, portmap = discover_portmap(deprecated, satisfied, portmap,
                                          support_path)
    # Parse bcm_counters.
    satisfied, bcm_counters = discover_bcm_counters(deprecated, satisfied,
                                                    bcm_counters, support_path)
    # Discover LLDP information.
    satisfied, lldp = discover_lldpctl(deprecated, satisfied, lldp,
                                       support_path)
    # Discover dhcrelay configs
    satisfied, services = discover_dhcrelay_conf(deprecated, satisfied,
                                                 cl_support, services)
    # Discover smonctl
    satisfied, smonctl = discover_smonctl(deprecated, satisfied, support_path)
    # Discover platform information.
    satisfied, discovered = discover_platform(deprecated, satisfied,
                                              discovered, support_path)
    satisfied, discovered, problems = discover_platform_detail(deprecated,
                                                               satisfied,
                                                               discovered,
                                                               includes,
                                                               problems)
    # Discover clagd.status
    satisfied, features = discover_clagd(deprecated, satisfied, features,
                                         support_path)
    # Discover v4 routes.
    satisfied, v4_routes = discover_v4_routes(deprecated, satisfied,
                                              support_path)
    satisfied, discovered = discover_control(deprecated, satisfied, cl_support,
                                             discovered)
    # Discover ip.addr
    satisfied, addresses = discover_addresses(deprecated, satisfied,
                                              support_path)
    # Discover zebra.intf
    satisfied, interfaces = discover_zebra_intf(deprecated, satisfied,
                                                interfaces, support_path)
    satisfied, features = discover_traffic_conf(deprecated, satisfied,
                                                cl_support, features)
    # Discover stp
    satisfied, features, interfaces = discover_stp(deprecated, satisfied,
                                                   features, interfaces,
                                                   support_path)
    # Discover young routes.
    satisfied, young_routes = discover_young_routes(deprecated, satisfied,
                                                    support_path)
    # Discover smart.
    satisfied, discovered = discover_smart(deprecated, satisfied, discovered,
                                           support_path)
    # Discover ports.conf.
    satisfied, discovered, features = discover_ports_conf(deprecated,
                                                          satisfied,
                                                          cl_support,
                                                          discovered, features)
    # discover cmdline.
    satisfied, features = discover_cmdline(deprecated, satisfied, cl_support,
                                           features)
    # Discover cpld info.
    satisfied, discovered = discover_cpld(deprecated, satisfied, discovered,
                                          support_path)
    # Discover Kernel version information.
    satisfied, discovered = discover_kernel(deprecated, satisfied, cl_support,
                                            discovered)
    # Discover ONIE info.
    satisfied, discovered = discover_onie(deprecated, satisfied, discovered,
                                          support_path)
    # Discover system date.
    satisfied, discovered = discover_date(deprecated, satisfied, discovered)
    # Discover bridges.
    satisfied, discovered = discover_bridges(deprecated, satisfied, bridges,
                                             discovered, interfaces)
    # Discover installed packages.
    satisfied, discovered = discover_dpkg(deprecated, satisfied, discovered,
                                          support_path)

    satisfied, discovered = discover_vnis(deprecated, satisfied, support_path,
                                          discovered)
    # Discover evpn routes...
    satisfied, discovered = discover_evpn_routes(deprecated, satisfied,
                                                 discovered, support_path)
    # Discover l3.defip...
    satisfied, discovered = discover_l3_defip(deprecated, satisfied,
                                              discovered, support_path)
    # Discover l3.egress...
    satisfied, discovered = discover_l3_egress(deprecated, satisfied,
                                               discovered, support_path)
    # Discover switchd.debug.vxlan.info...
    satisfied, discovered = discover_vxlan_info(deprecated, satisfied,
                                                discovered, support_path)
    # Discover BIOS information.
    satisfied, discovered = discover_bios(deprecated, satisfied, discovered,
                                          support_path)

    # Discover remote syslog configuration.
    satisfied, discovered = discover_remote_syslog(deprecated, satisfied,
                                                    discovered, cl_support)

    """Detection Functions"""
    # Warn for high interface discards.
    satisfied, high_discards, warnings = detect_high_discards(deprecated,
                                                              satisfied,
                                                              high_discards,
                                                              interfaces,
                                                              warnings)
    # Detect Mellanox SN2100 SMBIOS Error
    satisfied, discovered, problems = detect_mlx_smbios_error(deprecated,
                                                              satisfied,
                                                              support_path,
                                                              discovered,
                                                              problems)
    # Detect symmetric vxlan config on Spectrum A0 platforms.
    satisfied, warnings = detect_sym_vxlan_on_spectrum_v0(deprecated,
                                                          satisfied,
                                                          discovered, features,
                                                          warnings)
    # Detect OSPF Unnumbered misconfigurations.
    satisfied, problems = detect_ospf_unnumbered_misconfig(deprecated,
                                                           satisfied, features,
                                                           interfaces,
                                                           problems)
    # Detect dependent ports intersection.
    satisfied, problems = detect_dependent_ports_intersect(deprecated,
                                                           satisfied, bridges,
                                                           bonds, interfaces,
                                                           problems)
    # Detect sub-interface with parent in bridge that contains same vlan.
    satisfied, problems, warnings = detect_sub_int_bridge_vlan_collision(
        deprecated, satisfied, bridges,
        interfaces, subinterfaces,
        problems, warnings)
    # Detect misconfigurations related to Reserved VLAN Range.
    satisfied, problems = detect_resv_vlan_misconfigs(deprecated, satisfied,
                                                      interfaces, rvr,
                                                      problems)
    # Detect ipv4/ipv6 forwarding disabled in sysctl, frr, /e/n/i.
    satisfied, forwarding, warnings = detect_forwarding_disabled(deprecated,
                                                                 satisfied,
                                                                 features,
                                                                 forwarding,
                                                                 interfaces,
                                                                 warnings)
    # Detect failed services.
    satisfied, problems = detect_failed_services(deprecated, features,
                                                 satisfied, problems, services)

    # Detect if ARP timeout is longer than any of the bridge MAC DB timeout
    satisfied, problems = detect_arp_mac_timers_mismatch(deprecated, satisfied,
                                                         bridges, interfaces,
                                                         timers, problems)
    # Detect IPv4/IPv6 address configuration in FRR.
    satisfied, warnings = detect_frr_ip_config(deprecated, satisfied, features,
                                               warnings)
    # Detect redistribute neighbor misconfigs.
    satisfied, problems = detect_redist_neigh_misconfig(deprecated, satisfied,
                                                        features, interfaces,
                                                        problems, services)
    # Detect nondeterministic router-id.
    satisfied, warnings = detect_nondeterministic_routerid(deprecated,
                                                           satisfied, features,
                                                           warnings)
    # Detect bcm_counters that we care about.
    satisfied, warnings = detect_bcm_counters(deprecated, satisfied,
                                              bcm_counters, portmap, warnings)
    # Detect redistribution of EGP into IGP. (That's just STUPID!)
    satisfied, warnings = detect_egp_to_igp(deprecated, satisfied, features,
                                            warnings)
    # Detect static route leaking misconfig.
    satisfied, problems = detect_route_leak_misconfig(deprecated, satisfied,
                                                      discovered, features,
                                                      problems)
    # Detect warnings / problems from signatures in /var/log files.
    (satisfied, info, logs, regex_matches, problems, warnings,
     whitelisted) = detect_log_sigs(deprecated, satisfied, cl_support, info,
                                    problems, support_path, warnings)
    # Detect issues in smonctl.
    satisfied, logs, problems = detect_smonctl(deprecated, satisfied, smonctl,
                                               logs, problems)
    # Detect wrong ONIE.
    satisfied, problems = detect_wrong_onie_accton(deprecated, satisfied,
                                                   discovered, problems)
    # Detect clagd issues.
    satisfied, problems, warnings = detect_clagd_issues(deprecated, satisfied,
                                                        addresses, bridges,
                                                        features, interfaces,
                                                        problems, v4_routes,
                                                        warnings)
    satisfied, problems = detect_dhcrelay_probs(deprecated, satisfied,
                                                interfaces, services,
                                                problems, v4_routes)
    # Detect unsupported routing protocols.
    satisfied, warnings = detect_unsupported_protocols(deprecated, satisfied,
                                                       features, warnings)
    # Detect ?excessive? link flaps.
    satisfied, warnings = detect_link_flaps(deprecated, satisfied, cl_support,
                                            interfaces, warnings)
    # Detect link_pause is enabled.
    satisfied, warnings = detect_link_pause(deprecated, satisfied, features,
                                            warnings)
    # Detect core files.
    satisfied, info = detect_core_files(deprecated, satisfied, cl_support,
                                        info)
    # Detect LNV and VxLAN both configured.
    satisfied, warnings = detect_lnv_vxlan(deprecated, satisfied, features,
                                           services, warnings)
    # Detect unlicensed switches.
    satisfied, discovered, problems = detect_unlicensed(deprecated, satisfied,
                                                        discovered, problems)
    # Detect interfaces in discarding state.
    satisfied, warnings = detect_stp_discarding(deprecated, satisfied,
                                                features, warnings)
    satisfied, info = detect_young_routes(deprecated, satisfied, info,
                                          young_routes)
    # Detect 3IE3/3ME3/3IE4 drives mounted without discard option.
    satisfied, problems = detect_3ie3_3me3_discard(deprecated, satisfied,
                                                   discovered, problems,
                                                   warnings)
    # Detect unsupported VXLAN routing.
    satisfied, problems, warnings = detect_unsupported_vx_routing(deprecated,
                                                                  satisfied,
                                                                  discovered,
                                                                  features,
                                                                  interfaces,
                                                                  problems,
                                                                  warnings)
    # Detect ports_conf issues.
    satisfied, problems, warnings = detect_ports_conf(deprecated, satisfied,
                                                      discovered, problems,
                                                      warnings)
    satisfied, problems, warnings = detect_subint_misconfigs(deprecated,
                                                             satisfied,
                                                             interfaces,
                                                             problems,
                                                             warnings)
    satisfied, warnings = detect_spectre_meltdown(deprecated, satisfied,
                                                  discovered, features,
                                                  warnings)
    # Detect missing route-maps.
    satisfied, problems = detect_missing_route_maps(deprecated, satisfied,
                                                    discovered, problems)
    # Detect missing route-maps.
    satisfied, problems = detect_missing_prefix_lists(deprecated, satisfied,
                                                      discovered, problems)
    # Detect broken CL version.
    satisfied, problems = detect_broken_cl(deprecated, satisfied, discovered,
                                           problems)
    # Detect hsflowd on AS4610.
    satisfied, problems = detect_hsflow_unsupported(deprecated, satisfied,
                                                    discovered, problems,
                                                    services)
    # Detect dup-ip-mac mappings...
    satisfied, warnings = detect_dup_ip_mac(deprecated, satisfied,
                                            support_path, warnings)
    # Detect test packages.
    satisfied, warnings = detect_test_pkgs(deprecated, satisfied, discovered,
                                           warnings)
    # Detect bad system clock.
    # satisfied, problems = detect_bad_sysclock(deprecated, satisfied,
    #                                          discovered, problems)
    # Disabled until the bug can be squashed:
    # cl_support__R22-SPINE-A_20190517_151414, Case 10303

    # End calls to Detection Functions.

    # Expansion functions.
    # Expand FRR EC's:
    satisfied, problems, suggestions = expand_frr_ec(deprecated, satisfied,
                                                     includes, problems,
                                                     regex_matches)
    # Check for cm-26383.
    satisfied, problems = detect_cm26383(deprecated, satisfied, discovered,
                                         interfaces, problems)

    # Look for remote VTEPs via sub-interface...
    satisfied, problems = detect_vxlan_bad_path(deprecated, satisfied,
                                                discovered, problems, svis,
                                                v4_routes)

    # Detect >2000 VLANs on Spectrum...
    satisfied, problems = detect_toomany_vlans(deprecated, satisfied,
                                               discovered, problems,
                                               vlans_inuse)

    # Detect bad GPORT programming...
    satisfied, problems = detect_bad_gport(deprecated, satisfied, discovered,
                                           problems)

    # Detect remote TCP syslog server potentially causing memory leak (CM-19292)
    satisfied, warnings = detect_tcp_rsyslog(deprecated, satisfied, discovered,
                                            warnings)

    # This is always the last to run in Zulu.
    satisfied, info = wisdom(deprecated, satisfied, info)
    # Add eth0 IP address to discovered if we know it:
    if 'addresses' in locals() and 'eth0' in addresses:
        discovered['eth0_ip'] = addresses['eth0']

    """Output"""
    # Format our output struct.
    output = {}
    if len(args_dict['show']) < 1:
        # If there is not a list to show, we show them all!
        output_fields = all_fields
    else:
        output_fields = args_dict['show']
    if len(args_dict['exclude']) > 0:
        # If we've been told to exclude a field, exclude it!
        for item in args_dict['exclude']:
            if item in output_fields:
                output_fields.remove(item)
    # Build output based on the fields remaining in output_fields.
    for item in output_fields:
        if (item in locals() and locals()[item] is not None and len(
                locals()[item]) > 0):
            output[item] = locals()[item]
    return (output)


if __name__ == '__main__':
    # This file is never intended to be run directly.
    args_dict = []
    args_dict['verbose'] = True
    _ = defaults(args_dict)
    logger.error('The turbo_entabulator.py file is not intended to be run'
                 'directly.')
    exit(code=1)
