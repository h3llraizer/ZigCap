
iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
