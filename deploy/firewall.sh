#!/bin/sh
# Add only this application's public ports; never flush existing rules or touch SSH.
set -eu
for tool in iptables ip6tables; do
    if ! "$tool" -w 10 -S INPUT >/dev/null 2>&1; then
        if [ "$tool" = ip6tables ] && [ ! -e /proc/net/if_inet6 ]; then continue; fi
        echo "$tool is unavailable; cannot configure host firewall" >&2; exit 1
    fi
    "$tool" -w 10 -S ORCA-RELAY-IN >/dev/null 2>&1 || "$tool" -w 10 -N ORCA-RELAY-IN
    for port in 80 443; do
        "$tool" -w 10 -C ORCA-RELAY-IN -p tcp --dport "$port" -j ACCEPT 2>/dev/null ||
            "$tool" -w 10 -A ORCA-RELAY-IN -p tcp --dport "$port" -j ACCEPT
    done
    "$tool" -w 10 -C INPUT -j ORCA-RELAY-IN 2>/dev/null || "$tool" -w 10 -I INPUT 1 -j ORCA-RELAY-IN
done
