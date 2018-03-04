import dpkt
import struct


f = open('assignment.pcap')
pcap = dpkt.pcap.Reader(f)

count = 0
for ts, buf in pcap:
	count += 1
print count