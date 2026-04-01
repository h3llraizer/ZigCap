# ZigCap
A packet capture and parsing utility.

# Where I'm currently at
It's not ready to be used in a real networking project yet. But it will be soon enough.
I've implemented enough features to send some basic packets (IP/UDP/Eth/ARP) with simple payloads.
I'm currently adjusting the packet data ownership model in Packet and Layer (and then WirePacket) so memory management is explicit and makes sense and then I'll expose it as a lib.

Feel free to poke around.
