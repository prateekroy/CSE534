import dpkt
import struct
import Queue

class NotValidPacket(Exception):
    pass

#Reference : https://pymotw.com/2/struct/
def getField(buf, fmt, pos, size):
	if(len(buf) > pos):
		return str(struct.unpack(fmt, buf[pos:pos+size])[0])
	raise NotValidPacket

class Packet:
	isValid = True
	headerSize = ""
	srcIp = ""
	destIp = ""
	srcPort = ""
	destPort = ""
	syn = ""
	ack = ""
	wndsize = ""
	seqNum = ""
	ackNum = ""
	size = ""
	timestamp = 0
	request = ""
	response = ""
	data = ""

	#Reference : http://www.networksorcery.com/enp/protocol/tcp.htm
	def parsetcp(self, timestamp, buf):
		try:
			self.headerSize = getField(buf, ">B", 46, 1)
			self.srcIp = getField(buf, ">B", 26, 1) + \
							"." + getField(buf, ">B", 27, 1) + \
							"." + getField(buf, ">B", 28, 1) + \
							"." + getField(buf, ">B", 29, 1)

			self.destIp = getField(buf, ">B", 30, 1) + \
							"." + getField(buf, ">B", 31, 1) + \
							"." + getField(buf, ">B", 32, 1) + \
							"." + getField(buf, ">B", 33, 1)

			self.srcPort = getField(buf, ">H", 34, 2)
			self.destPort = getField(buf, ">H", 36, 2)
			option = "{0:16b}".format(int(getField(buf, ">H", 46, 2)))
			self.syn = option[14]
			self.ack = option[11]
			self.seqNum = getField(buf, ">I", 38, 4)
			self.ackNum = getField(buf, ">I", 42, 4)
			self.wndsize = getField(buf, ">H", 48, 2)
			self.size = len(buf)
			self.timestamp = timestamp
		except:
			self.isValid = False

	def parsehttp(self, timestamp, buf):
		try:
			self.request = str(getField(buf, ">s", 66, 1)) + str(getField(buf, ">s", 67, 1)) + str(getField(buf, ">s", 68, 1))
			self.response = str(getField(buf, ">s", 66, 1)) + str(getField(buf, ">s", 67, 1)) + str(getField(buf, ">s", 68, 1)) + str(getField(buf, ">s", 69, 1))
		except:
			pass        #it may happen that it is not a http header

def ParsePcapFile(pcap):
	db = []
	for timestamp, buf in pcap:
		packet = Packet()
		packet.parsetcp(timestamp, buf)
		packet.parsehttp(timestamp, buf)
		if packet.isValid:	
			db.append(packet) #few of packet are invalid because of emtpy fields or packet len small
 
	return db

def CheckHTTP(db):
	#Count the number of TCP connections
	tcpconnections = 0
	packetCount = 0
	totalPayload = 0
	for packet in db:
		packetCount += 1
		totalPayload += packet.size
		if packet.syn == "1" and packet.ack == "1":
			# print packet.srcIp + ":" + packet.srcPort + "-->" + packet.destIp + ":" + packet.destPort + "  " + packet.seqNum + "  " + packet.ackNum
			tcpconnections += 1
	
	print "No of tcp connections : " + str(tcpconnections)
	print "Time Taken : " + str(db[len(db)-1].timestamp-db[0].timestamp)
	print "Packet Count : " + str(packetCount)
	print "Raw data size : " + str(totalPayload)


def Task1(db):
	que = Queue.Queue()
	responseDict = {}

	for packet in db:
		if packet.request == "GET":
			que.put(packet)
		elif packet.response == "HTTP":
			deq = que.get()
			responseDict[deq] = packet

	for key, value in responseDict.iteritems():
		print "GET           " + key.srcIp + " " + key.destIp + " " + key.seqNum + " " + key.ackNum
		print "HTTP RESPONSE " + value.srcIp + " " + value.destIp + " " + value.seqNum + " " + value.ackNum


def FormPair(file):
	pcap = dpkt.pcap.Reader(open(file))
	db = ParsePcapFile(pcap)
	Task1(db)


def main():
	
	FormPair('http_1080.pcap')	

	files = ['http_1080.pcap','tcp_1081.pcap', 'tcp_1082.pcap']
	print "----------------------------------------------------------------------------------"
	# file = open('http_1080.pcap')
	# file = open('tcp_1081.pcap')
	# file = open('tcp_1082.pcap')
	for file in files:			
		pcap = dpkt.pcap.Reader(open(file))

		db = ParsePcapFile(pcap)
		# count = 0		
		# for packet in db:
		# 	if packet.request == "GET":
		# 		# print packet.srcIp + ":" + packet.srcPort
		# 		print "GET" + packet.srcIp + ":" + packet.srcPort + "-->" + packet.destIp + ":" + packet.destPort + "  " + packet.seqNum + "  " + packet.ackNum
		# 	if packet.response == "HTTP":
		# 		print "HTTP" + packet.srcIp + ":" + packet.srcPort + "-->" + packet.destIp + ":" + packet.destPort + "  " + packet.seqNum + "  " + packet.ackNum
				
			# print packet.destIp + ":" + packet.destPort
			# print packet.wndsize
			# print packet.seqNum
			# print packet.request
			# if count == 30:
				# break
		# 	count += 1

		# print count

		CheckHTTP(db)
		print "----------------------------------------------------------------------------------"
	


if __name__ == '__main__':
	main()