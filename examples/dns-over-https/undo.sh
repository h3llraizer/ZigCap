
iptables -D OUTPUT -s 192.168.1.225 -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
