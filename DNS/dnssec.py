import dns.resolver
import dns.query
import dns.dnssec
import time
import datetime
import sys
#https://www.iana.org/domains/root/servers
def GetRootServerList():
	return ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33'];

def GetTLD(domain):

	rrset = None
	child_ds = None
	child_algo = None

	for rootServer in GetRootServerList():
		# print rootServer
		if ValidateRootServers(rootServer):
			# print "validated"
			rrset, child_ds, child_algo = GetNextLevelServers(domain, rootServer)
			if rrset:
				break

	return rrset, child_ds, child_algo

#Check if the root server is validated
def ValidateRootServers(server):
	#http://data.iana.org/root-anchors/root-anchors.xml
	root_dslist = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5', '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
	RRsig, RRset, ZSK = GetZSK('.', server)
	if not ZSK or not RRsig or not RRset:
	    return False

	hash = dns.dnssec.make_ds('.', ZSK, 'sha256')
	# print hash

	#validate using two step verification
	return TwoStepValidation('.', str(hash), root_dslist, RRsig, RRset)



#https://stackoverflow.com/questions/4066614/how-can-i-find-the-authoritative-dns-server-for-a-domain-using-dnspython/4066624
def GetNextLevelServers(domain, server):
	# print domain + " - " + server + " - "
	response = SendTCPQuery(domain, dns.rdatatype.DNSKEY, server, True)
	if not response:
		return None

	# print "-----------------------------------------------------"
	# print response
	# print "-----------------------------------------------------"


	child_ds,child_algo = ParseAuthoritySection(response)

	#if there is answer section or there is soa type in authority field this is our server IP
	if (len(response.answer) > 0 or ((len(response.authority) > 0) and (response.authority[0].rdtype == dns.rdatatype.SOA))):
		return [server], child_ds, child_algo
	
	#Check for addition fields first as they might have direct IPs
	res = ParseAdditionalSection(response)
	if res:
		return res, child_ds, child_algo

	#corner case
	#Do check for authority section if none hit above as google.co.jp might have some authoritative NS
	#If found Resolve it like previous
	authoritative_ns = ParseAuthoritySectionForNS(response)
	if authoritative_ns:	
		# print authoritative_ns
		return resolve(authoritative_ns), child_ds, child_algo

	return [], None, None

def ParseRRsigSection(answer):
	if len(answer) == 0:
		return None

	for entry in answer:
		if (entry.rdtype == dns.rdatatype.RRSIG):
			return entry

	return None

def ParseDNSKeySection(answer):
	if len(answer) == 0:
		return None, None

	for entry in answer:
		if (entry.rdtype == dns.rdatatype.DNSKEY):
			# print entry
			for record in entry:
				if record.flags == 257:   #257 is KSK, 256 is ZSK
					return entry, record

	return None, None

def ParseAuthoritySection(response):
	child_ds = None
	child_algo = None
	
	if len(response.authority) > 0:
		#Extract the DS field of authorative section for child and algorithm
		for auth in response.authority:
			if (auth.rdtype == dns.rdatatype.DS):
				child_ds = auth[0]
				if (auth[0].digest_type == 1):
					child_algo = "sha1"
				elif (auth[0].digest_type == 2):
					child_algo = "sha256"
				# break

	return child_ds, child_algo

def ParseAdditionalSection(response):
	res = []
	if(len(response.additional) > 0):
		for add in response.additional:
			res.append(add[0].to_text())
	
	return res

def ParseAuthoritySectionForNS(response):
	if len(response.authority) > 0:
		#pick the first authoritative server ;to do: check for other ns if any fails
		if len(response.authority[0]) > 0:
			return  response.authority[0][0].to_text()

	return None

def SendTCPQuery(domain, type, toserver, dnssecflag):
	try:
		query = dns.message.make_query(domain, type, want_dnssec = dnssecflag)
		return dns.query.tcp(query, toserver, timeout=10)
	except:
		return None

def GetZSK(domain, server):

    try:
		query = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
		response = dns.query.tcp(query, server, timeout=10)
		if (response.rcode() != dns.rcode.NOERROR):
		    raise Exception('ERROR')

		# print "******************************************************"
		# print response
		# print "******************************************************"

		RRsig = ParseRRsigSection(response.answer)
		RRset, ZSK = ParseDNSKeySection(response.answer)
		return RRsig, RRset, ZSK

    except Exception:
        return None, None, None


def SplitDomain(dom):
	domain = dns.name.from_text(dom)
	domainList = str(domain).split('.')
	domainList = domainList[:-1]
	return list(reversed(domainList))

def Validate(domain, ZSK, RRsig, RRset, child_ds, child_algo):
	if child_algo and child_ds and ZSK and RRsig:
	    hash_key = dns.dnssec.make_ds(domain, ZSK, child_algo)
	    return TwoStepValidation(domain, hash_key, [child_ds], RRsig, RRset)
	else:
		print "DNSSEC not supported"
		return False

def TwoStepValidation(domain, hash, dslist, RRsig, RRset):
	#step 1: verify the hash with parent ds
	hashverified = False;
	for ds in dslist:
		if ds == hash:
			hashverified = True

	if not hashverified:
		print "DNSSec verification failed"
		return False

	#step 2 : if ds matches check for validating the public key
	try:
		dns.dnssec.validate(RRset, RRsig, {dns.name.from_text(domain): RRset})
	except dns.dnssec.ValidationFailure:
		print "DNSSec verification failed"
		return False

	return True

def PopulateNextLevelServers(currLevelServers, query):
	for server in currLevelServers:
		try:
			nextLevelServers, child_ds, child_algo = GetNextLevelServers(query, server)
			if (nextLevelServers):
				return nextLevelServers, child_ds, child_algo
		except:
			pass

	return [], None, None

#https://www.grepular.com/Understanding_DNSSEC
def resolve(name):
	domainHier = SplitDomain(name)

	query = domainHier[0]+"."
	currLevelServers, child_ds, child_algo = GetTLD(query)
	

	for domain in domainHier[1:]:
		ZSK = None
		RRset = None
		RRsig = None

		for server in currLevelServers:
			RRsig, RRset, ZSK = GetZSK(query, server)
			if ZSK and RRsig and RRset:
				break

		if not Validate(query, ZSK, RRsig, RRset, child_ds, child_algo):
			return None

		query = domain + '.' + query
		# print "Next Try" + query

		# print currLevelServers
		if not currLevelServers:
			break

		nextlevelServers, child_ds, child_algo = PopulateNextLevelServers(currLevelServers, query)
		currLevelServers = nextlevelServers

	return currLevelServers


# 216.239.34.10
def _mydig(name):
	servers = resolve(name)

	if not servers:
		return None

	for server in servers:
		# print server
		result = SendTCPQuery(name, "A", server, False)
		if result:
			return result

	return None


def Format(result, query_time):
	rrset = result.answer[0]
	rr = rrset[0]	
	if(rr.rdtype == dns.rdatatype.CNAME):
		cname_ans = _mydig(str(rr))
		result.answer += cname_ans.answer

	output = ""

	output += "QUESTION SECTION:\n" + result.question[0].to_text() + "\n\n" + "ANSWER SECTION:\n"

	for ans in result.answer:
		output += ans.to_text()

	output += "\n\n" + "Query Time: "
	output += str(query_time) + " sec\n"

	currentDT = datetime.datetime.now()
	output += currentDT.strftime("%a %b %d %H:%M:%S %Y\n")

	output += "MSG SIZE rcvd: " + str(sys.getsizeof(result))

	return output


def mydig(name):
	#profiling
	start_time = time.time()
	result = _mydig(name)
	time_taken = time.time() - start_time
	if result:
		return Format(result, time_taken)
	else:
		return ""


if __name__ == '__main__':
	domain = sys.argv[1]
	# domain = "www.cnn.com"
	print mydig(domain)
	# query = dns.message.make_query("www.google.com", "A")
	# response = dns.query.udp(query, "216.239.34.10", timeout=1)
	# print response
	# print Format(mydig("www.google.com", "A"), "A")
	# print mydig("verisigninc.com")
	# print mydig("google.com")
	# print mydig("www.dnssec-failed.org")
	# print mydig("dnssec-tools.org")
	# print mydig("dnssec-deployment.org")

	

	