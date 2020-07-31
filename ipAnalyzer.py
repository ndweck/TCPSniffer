from Analyzer import Analyzer
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import math
import time

PEAK_SECONDS = 10
STD_THRESHOLD = 1.5

engine = create_engine('sqlite:///test.db', echo=True)
Base = declarative_base()


class IpAnalyzer(Analyzer):
    """
    performs an anomaly analysis of the TCP packets according to the destination IP and port
    """

    def __init__(self):
        """
        initializer
        """
        self.ips = {}
        self.ports = {}
        self.Session = sessionmaker(bind=engine)
        self.anomal_ips = []
        self.anomal_ports = []

    def analyze(self, raw_data):
        """
        analyzes all the packets from the raw_data repository. and saves an internal report.
        :param raw_data: a raw data repository which supports an iterator interface
        :return: None
        """
        for packet in raw_data:
            # add to IP dictionary
            if self.ips.get(packet.ip_dst) is None:
                # new ip
                self.ips[packet.ip_dst] = IpData(packet.ip_dst, packet.payload_size, packet.curr_time)
            else:
                # update ip
                self.ips[packet.ip_dst].add_packet(packet.payload_size, packet.curr_time)
            # add to port dictionary
            if self.ports.get(packet.tcp_dport) is None:
                # new port
                self.ports[packet.tcp_dport] = IpData(packet.tcp_dport, packet.payload_size, packet.curr_time)
            else:
                # update port
                self.ports[packet.tcp_dport].add_packet(packet.payload_size, packet.curr_time)
        self.calculate_ip_anomalies()
        self.calculate_port_anomalies()

    def calculate_ip_anomalies(self):
        """
        calculate the ip bandwidth anomalies.
        calculate the mean and STD bandwidth and compare the current measurement.
        :return:
        """
        # load data from database
        ip_session = self.Session()
        old_ips = ip_session.query(IPPersistData).all()
        for ip_data in old_ips:
            # for each of the ip's we have historical data - calculate the mean and STD and check for anomaly
            if self.ips.get(ip_data.ip) is not None:
                current_data = self.ips[ip_data.ip]
                mean = ip_data.bytes // ip_data.tx_time
                # get old measurements so we can calculate the STD
                measurements_session = self.Session()
                old_measurements = measurements_session.query(IpPersistHistory).\
                    filter(IpPersistHistory.ip == ip_data.ip).all()
                std_sum = 0
                for measurement in old_measurements:
                    std_sum += math.pow(measurement.bandwidth - mean, 2)
                std = math.sqrt(std_sum)
                if current_data.get_bandwidth() > mean + STD_THRESHOLD * std or current_data.peak > ip_data.peak:
                    self.anomal_ips.append((ip_data.ip, current_data.get_bandwidth(),  mean, current_data.peak,
                                            ip_data.peak))
                # add new measurement to history measurements
                measurement = IpPersistHistory()
                measurement.bandwidth = current_data.get_bandwidth()
                measurement.ip = ip_data.ip
                measurements_session.add(measurement)
                measurements_session.commit()
                # update the IPPersistData object with the new measurement
                ip_data.update(current_data)
                # remove it from the measurements dictionary
                self.ips.pop(ip_data.ip, None)
        # loop over new ips
        for (ip, measurement) in self.ips.items():
            # add to report
            self.anomal_ips.append((ip, measurement.get_bandwidth(), 0, measurement.peak))
            # add to ip table
            ip_measurement = IPPersistData()
            ip_measurement.ip = ip
            ip_measurement.update(measurement)
            ip_session.add(ip_measurement)
            # add to ip historical measurements table
            hist_measurement = IpPersistHistory()
            hist_measurement.bandwidth = measurement.get_bandwidth()
            hist_measurement.ip = ip
            ip_session.add(hist_measurement)
        ip_session.commit()

    def calculate_port_anomalies(self):
        """
        calculate the port bandwidth anomalies.
        calculate the mean and STD bandwidth and compare the current measurement.
        :return:
        """
        # load data from database
        port_session = self.Session()
        old_ports = port_session.query(PortPersistData).all()
        for port_data in old_ports:
            # for each of the ip's we have historical data - calculate the mean and STD and check for anomaly
            if self.ports.get(port_data.port) is not None:
                current_data = self.ports[port_data.port]
                mean = port_data.bytes // port_data.tx_time
                # get old measurements so we can calculate the STD
                measurements_session = self.Session()
                old_measurements = measurements_session.query(PortPersistHistory).\
                    filter(PortPersistHistory.port == port_data.port).all()
                std_sum = 0
                for measurement in old_measurements:
                    std_sum += math.pow(measurement.bandwidth - mean, 2)
                std = math.sqrt(std_sum)
                if current_data.get_bandwidth() > mean + STD_THRESHOLD * std or current_data.peak > port_data.peak:
                    self.anomal_ports.append((port_data.port, current_data.get_bandwidth(),  mean, current_data.peak,
                                              port_data.peak))
                # add new measurement to history measurements
                measurement = PortPersistHistory()
                measurement.bandwidth = current_data.get_bandwidth()
                measurement.port = port_data.port
                measurements_session.add(measurement)
                measurements_session.commit()
                # update the IPPersistData object with the new measurement
                port_data.update(current_data)
                # remove it from the measurements dictionary
                self.ports.pop(port_data.port, None)
        # loop over new ips
        for (port, measurement) in self.ports.items():
            # add to report
            self.anomal_ports.append((port, measurement.get_bandwidth(), 0, measurement.peak))
            # add to ip table
            port_measurement = PortPersistData()
            port_measurement.port = port
            port_measurement.update(measurement)
            port_session.add(port_measurement)
            # add to ip historical measurements table
            hist_measurement = PortPersistHistory()
            hist_measurement.bandwidth = measurement.get_bandwidth()
            hist_measurement.port = port
            port_session.add(hist_measurement)
        port_session.commit()

    def report(self):
        """

        :return: a tuple with the anomalies found for destination IPs and destination ports
        """
        return self.anomal_ips, self.anomal_ports


class AnalyzedData:
    """
        base class for analyzed data
    """
    def __init__(self, payload_size, packet_time):
        """
        initialyzer
        :param payload_size: the size of the packet's payload
        :param packet_time: the time of the packet (Float from epoch
        """
        self.payload_size = payload_size
        self.start_time = packet_time
        self.end_time = packet_time
        # save all the packets in the last PEAK_SECONDS seconds to calculate peak transmission
        self.packets = [(payload_size, packet_time)]
        self.peak = 0
        self.calculate_peak()

    def add_packet(self, payload_size, packet_time):
        """
        add new data of a packet
        :param payload_size: the size of the packet's payload
        :param packet_time: the time of the packet (Float from epoch
        :return: None
        """
        self.payload_size += payload_size
        self.end_time = packet_time
        self.packets.append((payload_size, packet_time))
        self.calculate_peak()

    def calculate_peak(self):
        """
        calculates the peak transmission in the last PEAK_SECONDS and removes
        the old packets from the list
        :return: None
        """
        oldest_time = self.packets[-1][1] - PEAK_SECONDS
        total_size = 0
        start_time = 0
        new_list = []
        for size, packet_time in self.packets:
            if packet_time > oldest_time:
                new_list.append((size, packet_time))
                total_size += size
                if start_time == 0:
                    start_time = packet_time
        current_peak = total_size // PEAK_SECONDS
        if current_peak > self.peak:
            self.peak = current_peak
        self.packets = new_list

    def get_bandwidth(self):
        """
        calculates and returns the analyzed bandwidth
        :return: the analyzed bandwidth
        """
        my_time = (self.end_time - self.start_time)
        if my_time == 0:
            my_time = 1
        return self.payload_size // my_time

    def get_transmission_time(self):
        """
        :return: the total transmission time
        """
        transmission_time = self.end_time - self.start_time
        if transmission_time == 0:
            transmission_time = 1
        return transmission_time


class IpData(AnalyzedData):
    """
    Analyzed data by IP
    """
    def __init__(self, ip, payload_size, tx_time):
        super().__init__(payload_size, tx_time)
        self.ip = ip


class Portdata(AnalyzedData):
    """
    analyzed data by port
    """
    def __init__(self, port, payload_size, tx_time):
        super().__init__(payload_size, tx_time)
        self.port = port


class IPPersistData(Base):

    __tablename__ = 'iptraffic'

    ip = Column(String, primary_key=True)
    bytes = Column(Integer)
    tx_time = Column(Float)
    peak = Column(Float)
    last_update = Column(Float)

    def __repr__(self):
        return "<User(ip='%s', bytes='%d', time='%f', peak='%f', last_update='%s')>" % (
            self.ip, self.bytes, self.tx_time, self.peak, self.last_update)

    def update(self, measured):
        """
        update this instance with a new measurement
        :param measured: the new measurement - an  AnalyzedData instance
        :return: None
        """
        if self.bytes is None:
            self.bytes = 0
        self.bytes += measured.payload_size
        if self.tx_time is None:
            self.tx_time = 0
        self.tx_time += measured.get_transmission_time()
        if self.peak is None:
            self.peak = 0
        if measured.peak > self.peak:
            self.peak = measured.peak
        self.last_update = time.time()


class PortPersistData(Base):

    __tablename__ = 'porttraffic'

    port = Column(Integer, primary_key=True)
    bytes = Column(Integer)
    tx_time = Column(Float)
    peak = Column(Float)
    last_update = Column(Float)

    def __repr__(self):
        return "<User(port='%s', bytes='%d', time='%f', peak='%f', last_update='%s')>" % (
            self.port, self.bytes, self.tx_time, self.peak, self.last_update)

    def update(self, measured):
        """
        update this instance with a new measurement
        :param measured: the new measurement - an  AnalyzedData instance
        :return: None
        """
        if self.bytes is None:
            self.bytes = 0
        self.bytes += measured.payload_size
        if self.tx_time is None:
            self.tx_time = 0
        self.tx_time += measured.get_transmission_time()
        if self.peak is None:
            self.peak = 0
        if measured.peak > self.peak:
            self.peak = measured.peak
        self.last_update = time.time()


class IpPersistHistory(Base):

    __tablename__ = 'ipHistory'

    id = Column(Integer, primary_key=True)
    bandwidth = Column(Integer)
    ip = Column(String)

    def __repr__(self):
        return "<User(id='%d', ip='%s', bandwidth='%d')>" % (
            self.id, self.ip, self.bandwidth)


class PortPersistHistory(Base):

    __tablename__ = 'portHistory'

    id = Column(Integer, primary_key=True)
    bandwidth = Column(Integer)
    port = Column(Integer)

    def __repr__(self):
        return "<User(id='%d', ip='%d', bandwidth='%d')>" % (
            self.id, self.port, self.bandwidth)


class DummyPacket:
    """
    for testing purpose
    """
    def __init__(self, dport, dip, sport, sip, size, tx_time):
        self.tcp_dport = dport
        self.ip_dst = dip
        self.tcp_sport = sport
        self.ip_src = sip
        self.payload_size = size
        self.curr_time = tx_time


if __name__ == '__main__':
    analyzer = IpAnalyzer()
    Session = sessionmaker(bind=engine)
    session = Session()
    ips = session.query(IPPersistData).all()
    session.commit()
    if len(ips) == 0:
        # initial data
        analyzer.analyze([DummyPacket(80, '192.168.12.1', 321, '192.168.12.12', 30000, 300),
                          DummyPacket(80, '192.168.12.11', 80, '192.168.12.12', 30000, 300)])
    else:
        # traffic data
        analyzer.analyze([DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 300),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 301),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 302),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 312),
                          DummyPacket(80, '192.168.12.11', 80, '192.168.12.12', 30000, 300)])
        analyzer.analyze([DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 50000, 300),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 301),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 350000, 303),
                          DummyPacket(80, '192.168.12.1', 80, '192.168.12.12', 30000, 305),
                          DummyPacket(80, '192.168.12.11', 80, '192.168.12.12', 30000, 300)])
