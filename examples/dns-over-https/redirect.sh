#iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
#iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
