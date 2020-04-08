#!/usr/bin/env python3
"""
This is a test-harness for Turbo-Entabulator.

It demonstrates what you must import, how to set up the input structure,
host to bless the input structure with turbo_entabulator.defaults(),
how to run turbo_entabulator.zulu() and how to generate a report using
the built-in report generator.
"""

"""
You *MUST* import the following:
"""
from turbo_entabulator import turbo_entabulator

""""
If you want to use the report-generator that is built into Turbo-Entabulator,
you will need to import generate_report from turbo_entabulator.utilities:
"""
from turbo_entabulator.utilities import generate_report

"""
This import is not necessary but, its here in this test-harness so we can log
what the harness does using the logger.
"""
from turbo_entabulator.m_logger import logger

"""
This is not necessary.  Its only here to make some demo output pretty.
"""
import json

""" You *MUST* create an input struct to be blessed by
turbo_entabulator.defaults()
"""
input = {}

"""
If you want to deprecate something (typically a detection),
pass it in the following list.  You don't have to pass this list though as it
defaults to empty when you run turbo_entabulator.defaults().

In this example, we are disabling log signature detection(and
detect_3ie3_3me3_discard since it lists 'detect_log_sigs' as one of its reqs),
as well as 'wisdom' which is the TE-WISDOM code.
"""
input['deprecated'] = ['detect_log_sigs', 'wisdom']

"""
If you want to limit what gets returned from zulu, you can add the fields to
this list.  You don't have to pass this list though as it defaults to ALL
fields listed in 'all_fields' of turbo_entabulator.zulu.
"""
# input['show'] = []

"""
If you want to specifically exclude something from being returned from zulu,
you can add it to this list.  You don't have to pass this list though as it
defaults to empty when you run turbo_entabulator.defaults().
"""
# input['exclude'] = []

"""
If you want to turn on debugging, set input['verbose'] to True.
"""
input['verbose'] = True

"""
This is the only ***required*** field in the input structure you pass to
turbo_entabulator.defaults().  We need to know the root dirctory of the
cl_support to analyze.
"""
input['cl_support'] = '~/cases/vxlan/cl_support_mh-leaf01_20181003_153437/'

"""
You ***MUST*** run turbo_entabulator.defaults() passing it your input
structure.  It will validate the input structure as well as set up logging
and some defaults (deprecated, exclude, show) and 'bless' the input structure
so that turbo_entabulator.zulu() will accept it.

Note: Logging won't work until after this step since the logging level is
      set up in turbo_entabulator.defaults().
"""
input = turbo_entabulator.defaults(input)

"""
This is what turbo_entabulator.defaults() will return.

Note: You won't see anything here unless you have set input['verbose'] = True
"""
logger.debug(json.dumps(input, indent=2, sort_keys=True))

'''
This is where the magic happens.  Pass your input struct to
turbo_entabulator.zulu() and it will return a dict.  You can turn 'results'
into pretty JSON output with:
json.dumps(result, indent=2, sort_keys=True)
'''
logger.debug('Running TE against {}'.format(input['cl_support']))
results = turbo_entabulator.zulu(input)

'''
If you want to use the built in report generator, here is an example.

Do you want the log samples?
'''
logs = True
'''
Do you want the expanded FRR Error Code Suggestions?
'''
frr_ec = True
'''
Pass the dict returned by turbo_entabulator.zulu() to generate_report() and it
will return the report in plain text.
'''
logger.debug('Generating Report')
dataout = generate_report(results, logs, frr_ec)

'''
And here is the report...
'''
print(dataout)
