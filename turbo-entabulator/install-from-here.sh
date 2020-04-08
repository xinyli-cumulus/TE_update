#!/bin/bash
echo "Installing package.  Edits will NOT be LIVE."
python setup.py build
pip3 uninstall -y -vvv turbo-entabulator
pip3 install -vvv .

