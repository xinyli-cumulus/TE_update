#!/usr/bin/env python3
"""Logging is configured here..."""

import logging
import sys

# Create a logger object
logger = logging.getLogger('turbo-entabulator')
# configure the handler to format the message and output to stdout
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
