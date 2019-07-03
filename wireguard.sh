#!/bin/bash
SERVER_PUB_IP=$1
SERVER_PORT=$2
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
EOF

cat << EOF > ~/wg0.conf
[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = 10.66.66.2/24,fd42:42:42::2/64
DNS = 213.73.91.35,8.8.8.8

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $SERVER_PUB_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0,::/0

PersistentKeepalive = 25
EOF

sysctl net.ipv4.ip_forward=1
sysctl net.ipv6.conf.all.forwarding=1
