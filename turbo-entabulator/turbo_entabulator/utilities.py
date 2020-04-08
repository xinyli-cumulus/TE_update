#!/usr/bin/env python3
"""
Turbo-Entabulator utilities.

This file contains utilities used by the Turbo-Entabulator suite that don't
fall under the 'detections' or 'discovery' categories.
"""

# Copyright(c) 2018, 2019, 2020 Cumulus Networks, Inc
# John Fraizer <jfraizer@cumulusnetworks.com>

import json
import os
import random
import re
import sys
from turbo_entabulator.m_logger import logger


def check_dependencies(funcname, required, satisfied): # noqa
    """
    Validate that list 'requirements' is a subset of list 'satisfied'.

    :param funcname
    :param required
    :param satisfied
    :return bool
    """
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    logger.debug("Checking dependencies: {} for function [{}]."
                 .format(required, funcname))
    if not set(required).issubset(set(satisfied)):
        missing = list(set(required).difference(set(satisfied)))
        logger.debug("Required dependencies {} for [{}] have not been "
                     "satisfied!".format(missing, funcname))
        return False
    else:
        logger.debug("Dependencies satisfied.")
        return True

def expand_frr_ec(deprecated, satisfied, includes, problems, # noqa
                  regex_matches):
    """
    Try to provide suggestions for ECs from FRR.

    :param deprecated:
    :param satisfied:
    :param includes:
    :param problems:
    :param regex_matches:
    :return:
    """
    # Get function name (accesses private sys function, no better way)
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return satisfied, problems, {}
    reqs = ['detect_log_sigs']
    if not check_dependencies(name, reqs, satisfied):
        return satisfied, problems, {}
    if 'Uncategorized FRR Error' not in regex_matches:
        logger.debug("No matches to look up! Skipping".format(name))
        return satisfied, problems, {}
    # variable initialization not needed
    # db = {}
    filename = includes + "/frr/ec.json"
    if not os.path.isfile(filename):
        logger.debug("Could not open {} .".format(filename))
        problems.append('* * * TE CONFIG ERROR * * * Could not find {}! '
                        'Please verify that Turbo-Entabulator '
                        'is installed properly.'.format(filename))
        return satisfied, problems, {}
    logger.debug('Reading in {}...'.format(filename))
    with open(filename) as fh:
        db = json.load(fh)
    fh.close()
    # Dict to hold suggestions.
    suggestions = []
    count = 0
    for match in regex_matches['Uncategorized FRR Error']:
        _, ec = match.split(' ')
        count = count + 1
        if count > 1:
            suggestions.append('-' * 76)
        # Does FRR contain the expanded error description?
        if ec in db:
            suggestions.append(match + ':\t' + db[ec]['title'])
            suggestions.append('Description:\t' + db[ec]['description'])
            suggestions.append('Suggestion:\t' + db[ec]['suggestion'])
        else:
            suggestions.append(match + ':\t' + 'Unknown Error Code')
            suggestions.append('Description:\t' + 'Not found in FRR error DB')
            suggestions.append('Suggestion:\t' + 'Please File bug with FRR '
                                                 'team to add detail for ' +
                               match)
            msg = ('FILE-A-BUG: [' + match + '] not found in FRR Error '
                                             'Codes. Please file a bug with '
                                             'FRR team to have error detail '
                                             'added.')
            problems.append(msg)

    satisfied.append(name)
    # Then, return:
    return satisfied, problems, suggestions

def find_frr_path(deprecated, satisfied, support_path):  # noqa
    # Determine the ?.show_running file we need to parse.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, None)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, None)
    frr_files = ['frr.show_running', 'quagga.show_running',
                 'Quagga.show_running', 'zebra.config']
    for F in frr_files:
        filename = support_path + F
        if os.path.isfile(filename):
            logger.debug("Found {} .".format(filename))
            satisfied.append(name)
            return (satisfied, filename)
    logger.debug("Unable to find ?.show_running file to parse FRR data!")
    return (satisfied, None)

def find_ifquery_path(deprecated, satisfied, support_path):  # noqa
    # Determine the ifquery file we need to parse.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, None)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, None)
    ifquery_files = ['ifquery', 'ifquery-a']
    for F in ifquery_files:
        filename = support_path + F
        if os.path.isfile(filename):
            logger.debug("Found {} .".format(filename))
            satisfied.append(name)
            return (satisfied, filename)
    logger.debug("Unable to find ifquery file to parse data!")
    return (satisfied, None)

def find_support_path(deprecated, satisfied, CL):  # noqa
    # This function verifies that we can find "support/" or "Support/"
    # in the cl_support directory that has been passed to the script. It will
    # return the full path to the support directory or False.
    # We're at the top of the food-chain here so, we have no dependencies.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return (satisfied, None)
    reqs = []
    if not check_dependencies(name, reqs, satisfied):
        return (satisfied, None)
    # We need to verify that the cl_support directory we were passed is
    # actually a directory.
    if not os.path.isdir(CL):
        logger.debug("{} is not a directory!".format(CL))
        return (satisfied, None)
    satisfied.append('CL')
    support_paths = ['Support/', 'support/']
    for P in support_paths:
        support_path = CL + "/" + P
        if os.path.isdir(support_path):
            logger.debug("Found {} .".format(support_path))
            satisfied.append(name)
            return (satisfied, support_path)
        else:
            logger.debug("{} is not a directory!".format(support_path))
    return (satisfied, None)


def generate_report(result, print_logs, print_suggestions): # noqa
    """
    Generate human readable report.
    """

    if not result:
        logger.error("Results are empty! Shit's broke!")
        exit(1)

    # Common section dividers
    section_start_divider = '='*76 + '\n'
    section_end_divider = '='*76 + '\n\n'

    # Generate the report
    interested = ['Script Version', 'hostname', 'eth0_ip', 'uptime',
                  'cl_support', 'Command line', 'Reason', 'license',
                  'lsb-release', 'image-release', 'upgraded with apt-get',
                  'sysinfo', 'platform.detect', 'switch-architecture',
                  'vendor', 'model', 'cpld_version', 'onie_version',  'bios',
                  'service_tag', 'chipset', 'ports', 'capabilities', 'caveats',
                  'datasheet'
                  ]
    msg = "[Overview]".center(76, '=') + '\n'
    for item in interested:
        if 'discovered' in result and item in result['discovered']:
            if 'sysinfo' in item:
                for item2 in result['discovered'][item]:
                    msg = msg + ('{:>21}: {}\n'
                                 .format(item2.upper(),
                                         result['discovered'][item][item2]))
            elif 'bios' in item:
                msg = msg + ('{:>21}: ['.format('BIOS'))
                for item2 in result['discovered'][item]:
                    msg = msg + (' {}: {} '
                                 .format(item2,
                                         result['discovered'][item][item2]))
                msg = msg + ' ]\n'

            else:
                msg = msg + ('{:>21}: {}\n'.format(item.upper(),
                                                   result['discovered'][item]))
    msg = msg + section_end_divider

    # print problems
    if 'problems' in result.keys():
        msg = msg + "[Problems]".center(76, '=') + '\n'
        for item in result['problems']:
            msg = msg + item + '\n'
        msg = msg + section_end_divider

    # print warnings
    if 'warnings' in result.keys():
        msg = msg + "[Warnings]".center(76, '=') + '\n'
        for item in result['warnings']:
            msg = msg + item + '\n'
        msg = msg + section_end_divider

    # print info
    if 'info' in result.keys():
        msg = msg + "[Informational]".center(76, '=') + '\n'
        for item in result['info']:
            msg = msg + item + '\n'
        msg = msg + section_end_divider

    # print logs
    if print_logs and 'logs' in result.keys():
        if 'problems' in result['logs'].keys():
            msg = msg + ('Logs of interest [Problems]:\n')
            msg = msg + section_start_divider
            for item in result['logs']['problems']:
                msg = msg + item + '\n'
            msg = msg + section_end_divider
        if 'warnings' in result['logs'].keys():
            msg = msg + ('Logs of interest [Warnings]:\n')
            msg = msg + section_start_divider
            for item in result['logs']['warnings']:
                msg = msg + item + '\n'
            msg = msg + section_end_divider
        if 'info' in result['logs'].keys():
            msg = msg + ('Logs of interest [Informational]:\n')
            msg = msg + section_start_divider
            for item in result['logs']['info']:
                msg = msg + item + '\n'
            msg = msg + section_end_divider

    # print frr error codes
    if print_suggestions and 'suggestions' in result.keys():
        msg = msg + ('Expanded FRR Error Codes:\n')
        msg = msg + section_start_divider
        for item in result['suggestions']:
            msg = msg + item + '\n'
        msg = msg + section_start_divider

    return msg

def glob_to_numbers(glob):  # noqa
    """
    Given a string containing single numbers and ranges, return a sorted
    list of deduplicated integers.
    glob - A string of digits and ranges
    >>> glob_to_numbers('3-4,7,10-12,17,22,4001-4003,7777,8000-8004')
    [3, 4, 7, 10, 11, 12, 17, 22, 4001, 4002, 4003, 7777, 8000, 8001, 8002,
        8003, 8004]
    """
    assert isinstance(glob, (str)), "glob={0}".format(glob)
    # Using split(',') instead of the replacement could yield empty strings in
    # the result.
    glob_list = glob.replace(',', ' ').split()
    numbers = set()
    range_re = re.compile(r"""^(\d+)-(\d+)$""")  # ex. 4-6
    for x in glob_list:
        if x.isdigit():
            numbers.add(int(x))
        else:
            range_match = range_re.match(x)
            if range_match is None:
                # The substring is neither a digit nor a range.
                print("Globs must consist of numbers or ranges, but {0} is "
                      "neither. We were given glob '{1}'.".format(x, glob))
                return []
            else:
                min_range = int(range_match.group(1))
                max_range = int(range_match.group(2))
                if max_range >= min_range:
                    numbers.update(range(min_range, max_range + 1))
                else:
                    # print("Glob \"{0}\" contains the invalid range \"{1}\"."
                    #       .format(glob, x))  # ex. 6-4
                    return []
    return sorted(numbers)  # A sorted list

def ifname_expand_glob(ifname):  # noqa
    if not isinstance(ifname, (str)):
        raise TypeError("This function takes a string and returns a list of "
                        "strings.  type(ifname)={0}".format(type(ifname)))
    return ifname_expand_glob_helper(ifname, [])


def ifname_expand_glob_helper(ifname, result):  # noqa
    """ This function is recursive. """
    if ifname == '':
        # Base case 1
        return result
    if not ifname_is_glob(ifname):
        # Base case 2: non-globish input
        result.append(ifname)
        return result
    # Get the first glob component.  This could be a single name, like "bridge"
    # or it could be a range with commas and hyphens.  For example, given
    # "swp1-7,9", get the entire string.
    # Given "swp1-7,9,eth0", get "swp1-7,9,".
    glob = ''
    # Subinterface base and range?
    m = (re.match(
        r"""(?P<base>[a-zA-Z0-9-]+?\-?(?:\d+s)?\d+\.)(?P<glob>(?:0(?!\d)|[1-9]\d*)((,|-)\d+)+,?)""",  # noqa
        ifname))  # noqa
    if m is None:
        # Non-subinterface base and range?
        m = (re.match(
            r"""(?P<base>[a-zA-Z0-9-]+?\-?(?:\d+s)?)(?P<glob>(?:0(?!\d)|[1-9]\d*)((,|-)\d+)+,?)""",  # noqa
            ifname))  # noqa
        if m is None:
            m = re.match(r"""(?P<base>\S+?),""", ifname)
            if m is not None:
                # The input begins with a component that doesn't have a range.
                # Ex: lo, bridge, peer-group, Bond-T, server02, etc.
                glob = None
            else:
                raise ValueError("Couldn't parse '{0}'.".format(ifname))
    # Append the expanded substring of interfaces to the result.
    base = m.group('base')
    assert not ifname_is_glob(base), "base = {0}".format(base)
    if glob is None:
        # Append a single interface name to the result.
        result.append(base)
    else:
        # Append a multiple interface names to the result.
        glob = m.group('glob').rstrip(',')
        for number in glob_to_numbers(glob):
            result.append('{0}{1}'.format(base, number))
    # Recurse with the remaining input string.
    return ifname_expand_glob_helper(ifname[len(m.group()):], result)


def ifname_is_glob(ifname):  # noqa
    assert isinstance(ifname, str), "ifname={0}".format(ifname)
    # The empty string and strings with spaces are not globs.
    if not ifname or ' ' in ifname:
        return False
    if re.search(r"""\S,\S""", ifname) is not None:
        # Strings with comma-separated components are always a glob.
        return True
    # Strings with hyphens might be globs.
    re_range = re.search(r"""(?<!-)(\d+)-(\d+)(,|$)""", ifname)
    if re_range is not None:
        start_range = re_range.group(1)
        end_range = re_range.group(2)
        if ((len(start_range) > 1 and start_range.startswith('0')) or
                end_range.startswith('0')):
            # Valid ranges do not contain lead zeros.
            # '0' is not valid as the end range.
            return False
        if int(end_range) > int(start_range):
            return True
    return False


def test_check_dependencies(deprecated, satisfied): # noqa
    # This function tests the check_dependencies function.
    # This is a test list of satisfied modules.
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied)
    test = ['module1', 'module2']
    # This is a list of reqs that should be satisfied by test.
    should_pass = ['module1', 'module2']
    # This is a list of reqs that should not be satisfied by test.
    should_fail = ['module2', 'module3']
    if not check_dependencies('TEST: should_pass', should_pass, test):
        logger.error("ERROR! Function check_dependencies is broken! "
                     "False Negative")
        exit(1)
    if check_dependencies('TEST: should_fail', should_fail, test):
        logger.error("ERROR! Function check_dependencies is broken! "
                     "False Positive")
        exit(1)
    satisfied.append(name)
    return satisfied


def verify_path(path):
    """
    Verify the normalized directory or file path exists.

    :param path:
    :return normalized path:
    """
    path = os.path.abspath(os.path.expanduser(path))
    # if path location does not exist, exit.
    if not os.path.exists(path):
        logger.error("Filesystem path {} invalid.".format(path))
        exit(1)
    else:
        return path


def wisdom(deprecated, satisfied, info):
    """TE-WISDOM is just a fun little function that adds a one-liner."""
    name = sys._getframe().f_code.co_name
    logger.debug("This is {}().".format(name))
    if name in deprecated:
        logger.debug("[{}] is deprecated. Skipping".format(name))
        return(satisfied, info)
    reqs = ['find_support_path']
    if not check_dependencies(name, reqs, satisfied):
        return(satisfied, info)
    wisdom = [
        'This CL-SUPPORT Analysis is brought to you by Coors Light... '
        'Taste the Rockies!',
        '# rm -rf / ; reboot - Because its never too late to start again!',
        'Nothing makes a person more productive than the LAST MINUTE!',
        'I had my patience tested.  I\'m negative.',
        'Interviewer: "What do you make at your current job?" '
        'ME: "Mostly mistakes!"',
        'Dear Karma, I have a list of people you missed!!!',
        'Don\'t forget to shout "JENGA" when everything falls apart...',
        'Calories: Tiny creatures that live in your closet and sew your '
        'clothes a little tighter every night.',
        'A little bit goes a long way says the Big-Endian...',
        'My backup plan is just my original plan - with more ALCOHOL!',
        'Light travels faster than sound. This is why some people appear '
        'bright until you hear them speak.',
        'Silence is golden. Duct-tape is silver.',
        'If at first, you don\'t succeed, skydiving is not for you!',
        'My imaginary friend says that you need a therapist!',
        'My neighbor\'s diary says that I have boundary issues...',
        'I clapped because it\'s finished, not because I liked it.',
        'What do you mean I\'m not in shape? Round is a shape!',
        'I\'m smiling.  That alone should scare you!',
        'Common sense is a flower that doesn\'t grow in everyone\'s garden...',
        'Your trial license for Turbo-Entabulator has expired.  Generating '
        'random false-positives.',
        ]
    rand = random.randrange(0, len(wisdom))
    info.append('TE-WISDOM: {}'.format(wisdom[rand]))
    return(satisfied, info)
