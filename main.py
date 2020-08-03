# the main program python Code
from packetsStructure import *
import datetime
from scapy.all import *
import filter
from ipAnalyzer import *


PACKETS = 300
REPORT_FILE = '_report.txt'


def file_report(anomal_data, anomal_type):
    """
    print the anomalies report to a file. the file will override an existing report. the file name will have
    the anomal_type as a prefix.
    the file format is as follow:
    report time
    network anomaly traffic to <anomal_type>:
        <anomal_type>, bandwidth during snifiing, historical bandwidth, peak during sniffing, historical peak
    new <anomal_type>:
        <anomal_type>, bandwidth during snifiing, peak during sniffing
    :param anomal_data: anomaly data
    :param anomal_type: the report anomaly anomal_type
    :return: None
    """
    # check if file exists
    with open(anomal_type + REPORT_FILE, 'w') as report:
        report.write('Network anomaly report produced at ' + str(datetime.now()) + '\n')
        report.write('network anomaly traffic to ' + anomal_type + ':\n')
        report.write(anomal_type +
                     ', bandwidth during snifiing, historical bandwidth, peak during sniffing, historical peak\n')
        printed_new_traffic = False
        for traffic in anomal_data:
            if traffic[2] == 0:
                if not printed_new_traffic:
                    report.write('\n\nnew ' + anomal_type + ':\n')
                    report.write(anomal_type + ', bandwidth during snifiing, peak during sniffing\n')
                    printed_new_traffic = True
                report.write(str(traffic[0]) + ", " + str(traffic[1]) + ", " + str(traffic[3]) + '\n')
            else:
                report.write(str(traffic[0]) + ", " + str(traffic[1]) + ", " + str(traffic[2]) + ", " +
                             str(traffic[3]) + ", " + str(traffic[4]) + '\n')


def main():
    repository = PacketsStructure()
    filter.Filter(repository)
    # Sniff Packets. uses the Filter Class from filter.py
    sniff(lfilter=filter.Filter.filter_session, count=PACKETS)
    my_analyzer = IpAnalyzer()
    my_analyzer.analyze(repository)
    anomal_ip, anomal_port = my_analyzer.report()  # get the report and print to file

    print(anomal_ip)
    print(anomal_port)
    file_report(anomal_ip, 'ip')
    file_report(anomal_port, 'port')


if __name__ == '__main__':
    main()
