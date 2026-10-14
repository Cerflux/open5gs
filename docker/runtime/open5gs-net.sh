#!/bin/bash
# Prepare the host network namespace shared by every Open5GS process:
# the ogstun device, forwarding, and NAT for the UE pool.
set -eu

created=0
sleep_pid=

cleanup() {
    iptables -t nat -D POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE -m comment --comment open5gs 2>/dev/null || true
    ip6tables -t nat -D POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE -m comment --comment open5gs 2>/dev/null || true
    iptables -D FORWARD -i ogstun -j ACCEPT -m comment --comment open5gs 2>/dev/null || true
    iptables -D FORWARD -o ogstun -j ACCEPT -m comment --comment open5gs 2>/dev/null || true
    if [ "$created" -eq 1 ]; then
        ip link del ogstun 2>/dev/null || true
        created=0
    fi
    if [ -n "$sleep_pid" ]; then
        kill "$sleep_pid" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

# Bind mounts hide the image copies. Fill an empty host directory once.
seed_config() {
    src=$1
    dest=$2
    if [ ! -d "$src" ]; then
        echo "missing default config: $src" >&2
        exit 1
    fi
    mkdir -p "$dest"
    if [ -z "$(ls -A "$dest")" ]; then
        echo "seeding $dest from $src"
        cp -a "$src"/. "$dest"/
        chmod -R a+rwX "$dest"
    fi
}

seed_config /opt/open5gs/default-config /etc/open5gs
seed_config /opt/open5gs/default-freediameter /etc/freeDiameter

if ! grep -q 'ogstun:' /proc/net/dev; then
    ip tuntap add name ogstun mode tun
    created=1
fi

ip addr replace 10.45.0.1/16 dev ogstun
ip link set ogstun mtu 1400
ip link set ogstun up

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.disable_ipv6=0 || true
sysctl -w net.ipv6.conf.ogstun.disable_ipv6=0 || true
sysctl -w net.ipv6.conf.all.forwarding=1 || true

if ip addr replace 2001:db8:cafe::1/48 dev ogstun; then
    if ! ip6tables -t nat -C POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE -m comment --comment open5gs 2>/dev/null; then
        ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE -m comment --comment open5gs
    fi
else
    echo "IPv6 address on ogstun was not configured; IPv4 UE traffic still works" >&2
fi

if ! iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE -m comment --comment open5gs 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE -m comment --comment open5gs
fi
if ! iptables -C FORWARD -i ogstun -j ACCEPT -m comment --comment open5gs 2>/dev/null; then
    iptables -I FORWARD -i ogstun -j ACCEPT -m comment --comment open5gs
fi
if ! iptables -C FORWARD -o ogstun -j ACCEPT -m comment --comment open5gs 2>/dev/null; then
    iptables -I FORWARD -o ogstun -j ACCEPT -m comment --comment open5gs
fi

echo "ogstun is up. UE pool 10.45.0.0/16 via 10.45.0.1"
echo "AMF NGAP 127.0.0.5:38412/sctp  UPF GTP-U 127.0.0.7:2152/udp"
echo "MME S1AP 127.0.0.2:36412/sctp  SGW-U GTP-U 127.0.0.6:2152/udp"

# Stay in the foreground so this container keeps the network namespace alive.
sleep infinity &
sleep_pid=$!
wait "$sleep_pid" || true
