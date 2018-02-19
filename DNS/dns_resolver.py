import dns.resolver
import dns.query
import time
import datetime
import sys

#https://www.iana.org/domains/root/servers
def GetRootServerList():
	return ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33'];

#Get Top Level Domain IPs from root server
def GetTLD(domain, type):

	for rootServer in GetRootServerList():
		response = GetNextLevelServers(domain, rootServer, type)
		if response:
			break

	return response

#Split a URL by delimiter '.'
def SplitDomain(dom):
	domain = dns.name.from_text(dom)
	domainList = str(domain).split('.')
	domainList = domainList[:-1]
	return list(reversed(domainList))


#https://stackoverflow.com/questions/4066614/how-can-i-find-the-authoritative-dns-server-for-a-domain-using-dnspython/4066624
def GetNextLevelServers(domain, server, category):
	# print domain + " - " + server + " - "
	response = SendUDPQuery(domain, category, server)
	if not response:
		return None

	# print "-------------------------------------"
	# print response
	# print "-------------------------------------"

	#if there is answer section or there is soa type in authority field this is our server IP
	if (len(response.answer) > 0 or ((len(response.authority) > 0) and (response.authority[0].rdtype == dns.rdatatype.SOA))):
		return [server]
	
	#Check for addition fields first as they might have direct IPs
	res = ParseAdditionalSection(response)
	if res:
		return res

	#Do check for authority section if none hit above as google.co.jp might have some authoritative NS
	#If found Resolve it like previous
	authoritative_ns = ParseAuthoritySection(response)
	if authoritative_ns:	
		# print authoritative_ns
		return resolve(authoritative_ns, category)

	return []

def ParseAdditionalSection(response):
	res = []
	if(len(response.additional) > 0):
		for add in response.additional:
			res.append(add[0].to_text())
	
	return res

def ParseAuthoritySection(response):
	if len(response.authority) > 0:
		#pick the first authoritative server ;to do: check for other ns if any fails
		return  response.authority[0][0].to_text()

	return None

def PopulateNextLevelServers(currLevelServers, query, type):
	for server in currLevelServers:
		try:
			nextlevelServers = GetNextLevelServers(query, server, type)
			if nextlevelServers:
				return nextlevelServers
		except:
			pass

	return None

def SendUDPQuery(domain, type, toserver):
	try:
		query = dns.message.make_query(domain, type)	
		return dns.query.udp(query, toserver, timeout=1)	
	except:
		return None


def resolve(name, type):
	domainHier = SplitDomain(name)

	query = domainHier[0]+"."
	currLevelServers = GetTLD(query, type)
	
	if not currLevelServers:
		return []

	for domain in domainHier[1:]:
		query = domain + '.' + query
		# print "Next Try" + query

		# print currLevelServers 
		#if at any level we dont find servers we cannot resolve the dns
		if not currLevelServers:
			return []

		nextlevelServers = PopulateNextLevelServers(currLevelServers, query, type)
		currLevelServers = nextlevelServers

	return currLevelServers


def Format(result, type, query_time):
	if(len(result.answer)>0):
		rrset = result.answer[0]
		rr = rrset[0]	
		if(type == "A" and rr.rdtype == dns.rdatatype.CNAME):
			cname_ans = _mydig(str(rr), "A")
			result.answer += cname_ans.answer

	output = ""

	output += "QUESTION SECTION:\n" + result.question[0].to_text() + "\n\n" + "ANSWER SECTION:\n"

	for ans in result.answer:
		output += ans.to_text()+"\n"

	output += "\n" + "Query Time: "
	output += str(query_time) + " sec\n"

	currentDT = datetime.datetime.now()
	output += currentDT.strftime("%a %b %d %H:%M:%S %Y\n")

	output += "MSG SIZE rcvd: " + str(sys.getsizeof(result))

	return output


def _mydig(name, type):	
	servers = resolve(name, type)

	if not servers:
		return None

	for server in servers:
		# print server
		result = SendUDPQuery(name, type, server)
		if result:
			return result

	return None


def mydig(name, type):
	#profiling
	start_time = time.time()
	result = _mydig(name, type)
	time_taken = time.time() - start_time
	if result:
		return Format(result, type, time_taken)
	else:
		print "Cannot Resolve DNS!"


if __name__ == '__main__':
	domain = sys.argv[1]
	type = sys.argv[2]

	# domain = "google.co.jp"
	# type = "A"

	print mydig(domain, type)