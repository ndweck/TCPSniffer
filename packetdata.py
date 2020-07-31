from scapy.layers.inet import TCP, IP
import time


class PacketData:
    """
    parses a network TCP packet
    """

    packets = []  # List of Packets Data

    def __init__(self, pack):
        print('--------Packet #Number Added-------------')
        self.tcp_dport = pack[TCP].dport  # Destination PORT
        self.ip_dst = pack[IP].dst   # Destination IP
        self.tcp_sport = pack[TCP].sport  # Destination PORT
        self.ip_src = pack[IP].src  # Destination IP
        self.payload_size = len(pack[TCP].payload)
        self.curr_time = time.time()  # datetime.datetime.now() # Now Time
