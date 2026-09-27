#!/bin/bash
# Brings awg0 up (kernel module if the host has one, otherwise amneziawg-go), keeps it up, tears it down on stop.
CONF=/etc/amnezia/amneziawg/awg0.conf
until [ -f "$CONF" ]; do echo "waiting for $CONF (created by bootstrap)"; sleep 10; done
awg-quick down awg0 >/dev/null 2>&1 || true
awg-quick up awg0 || exit 1
echo "awg0 up: $(awg show awg0 | grep -m1 'listening port')"
trap 'echo stopping; awg-quick down awg0; exit 0' TERM INT
# restart the container if the interface disappears
while ip link show awg0 >/dev/null 2>&1; do sleep 15 & wait $!; done
echo "awg0 vanished"; exit 1
