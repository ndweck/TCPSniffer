from scapy.layers.inet import TCP, IP
import packetdata

packets = None


class Filter:
    """
    a filter that captures network traffic and stores it in a repository.
    """
    def __init__(self, repository):
        """
        initializes the instance with the data repository that will store the network packets
        :param repository:the repository to store the sniffed packets
        """
        global packets
        packets = repository

    # Filter just the TCP/IP Packets
    @staticmethod
    def filter_session(pack) -> bool:
        """
        filters TCP packets and stores them in the repository
        :param pack: the unfiltered packet
        :return: None
        """
        if IP in pack and TCP in pack:
            Filter.inspect_pack(pack)
            return True
        return False

    @classmethod
    def inspect_pack(cls, pack):
        """
        parses the packet to a packetData instance and stores it in the repository
        :param pack: the packet to be parsed
        :return:
        """
        global packets
        packets.add(packetdata.PacketData(pack))  # Refer to Create the Data from Packet
