#!/bin/sh
nft add table ip6 nat
nft add chain ip6 nat postrouting { type nat hook postrouting priority 100 \; }
nft add map ip6 nat usermap { type mark : ipv6_addr \; }
nft add rule ip6 nat postrouting snat to meta mark map @usermap