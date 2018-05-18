import dpkt
import struct


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
	mss = ""

	#Reference : http://www.networksorcery.com/enp/protocol/tcp.htm
	def parse(self, timestamp, buf):
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
			self.mss = getField(buf, ">H", 56, 2)
		except:
			self.isValid = False



def ParsePcapFile(pcap):
	db = []
	for timestamp, buf in pcap:
		packet = Packet()
		packet.parse(timestamp, buf)
		if packet.isValid:	
			db.append(packet) #few of packet are invalid because of emtpy fields or packet len small
 
	return db

def Task1(db):
	#Count the number of TCP connections
	tcpconnections = 0
	for packet in db:
		if packet.syn == "1" and packet.ack == "1":
			print "MSS : " + packet.mss
			tcpconnections += 1
	print "No of tcp connections : " + str(tcpconnections)


#Throughput
def Task2(db):
	once = True
	totalPayload = 0
	firstPacket = 0
	lastPacket = 0
	for packet in db:
		if packet.srcIp == "130.245.145.12":
			totalPayload += int(packet.size)
			if once:
				firstPacket = packet.timestamp
				once = False

			lastPacket = packet.timestamp

	# print "Total Payload : " + str(totalPayload)
	# print "Time difference : " + str(firstPacket), str(lastPacket)
	print "Throughput : " + str(totalPayload/(lastPacket-firstPacket))


class Connection:
	srcPort = ""
	destPort = ""
	packets = []
	def __init__(self, _src, _dest):
		self.srcPort = _src
		self.destPort = _dest
		# packet = []
		# self.packets.append(packet)

def ParseConnections(db):
	# connections = Connection()
	connections = []
	count = 0

	for packet in db:
		count += 1
		if packet.syn == "1" and packet.ack == "1":
			# print str(packet.srcPort) + ":" + str(packet.destPort) 
			connection = Connection(packet.srcPort, packet.destPort)
			connection.packets = []     #Damn!! It burned my day
			connections.append(connection)

	# print len(connections)
	# print count
	# for conn in connections:
	# 	print str(conn.srcPort) + ":" + str(conn.destPort) + ":" + str(len(conn.packets)) 

	for packet in db:
		for c in range(0,len(connections)):
			if (((packet.srcPort == connections[c].srcPort) and (packet.destPort == connections[c].destPort)) or \
					((packet.srcPort == connections[c].destPort) and (packet.destPort == connections[c].srcPort))):
				connections[c].packets.append(packet)
 
	# for c in range(0,len(connections)):
	# 	print str(connections[c].srcPort) + ":" + str(connections[c].destPort) + ":" + str(len(connections[c].packets)) 
	return connections


#--------------------------------PART B-------------------------------		
#Loss
def Task5(db):

	seqDict = {}
	ackDict = {}
	for packet in db:
		if packet.srcIp == "130.245.145.12" and packet.destIp == "128.208.2.198":
			seqDict[packet.seqNum] = seqDict.get(packet.seqNum,0) + 1
		elif packet.srcIp == "128.208.2.198" and packet.destIp == "130.245.145.12":
			ackDict[packet.ackNum] = ackDict.get(packet.ackNum,0) + 1

	loss = 0
	tripleAckLoss = 0
	for key, value in seqDict.iteritems():
		if key in seqDict:
			loss += seqDict[key]-1
		if (key in ackDict) and (ackDict[key] > 2):
			tripleAckLoss += seqDict[key]-1

	print "Duplicate Packet retransmitted : " + str(loss)
	print "Retransmissions due to Triple Ack Loss : " + str(tripleAckLoss)
	print "Loss due to timeout : " + str(loss-tripleAckLoss)


def Task6(db):
	count = 0
	congestionWnd = []
	for packet in db:
		if packet.srcIp == "130.245.145.12" and packet.destIp == "128.208.2.198":
			last_seq = packet.seqNum
		elif packet.srcIp == "128.208.2.198" and packet.destIp == "130.245.145.12" and int(last_seq)-int(packet.ackNum) != -1:
			congestionWnd.append(str(int(last_seq)-int(packet.ackNum)))
			if len(congestionWnd) == 10:
				break


	for conwnd in congestionWnd:
		print "Congestion Window : " + conwnd


def main():
	file = open('assignment2.pcap')
	pcap = dpkt.pcap.Reader(file)

	count = 0
	db = ParsePcapFile(pcap)

	#Find no of connections
	Task1(db)

	connections = ParseConnections(db)



	# for c in range(0,len(connections)):
	# 	print str(connections[c].srcPort) + ":" + str(connections[c].destPort) + ":" + str(len(connections[c].packets)) 


	#PART B
	for conn in connections:
		#Retransmissions , Triple Ack Loss
		Task5(conn.packets)

		#Congestion Window
		Task6(conn.packets)
		print "---------------------------------------------------------------------------------"

	# for packet in db:
		# print packet.srcIp + ":" + packet.srcPort + "-->" + packet.destIp + ":" + packet.destPort + "  " + packet.seqNum + "  " + packet.ackNum
		# print packet.destIp + ":" + packet.destPort
		# print packet.wndsize
		# print packet.seqNum
		# if count == 30:
			# break
		# count += 1

	# print count


	# Task2(db)



if __name__ == '__main__':
	main()

