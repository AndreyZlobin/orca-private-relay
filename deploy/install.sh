#!/bin/sh
set -eu
cd /opt/orca-private-relay
exec python3 deploy/install.py
