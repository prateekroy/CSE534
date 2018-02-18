import dns.resolver
import dns.query

#Change this from angellist
rootServerList = ['198.41.0.4',
                    '192.228.79.201',
                    '192.33.4.12',
                    '199.7.91.13',
                    '192.203.230.10',
                    '192.5.5.241',
                    '192.112.36.4',
                    '198.97.190.53',
                    '192.36.148.17',
                    '192.58.128.30',
                    '193.0.14.129',
                    '199.7.83.42',
                    '202.12.27.33']

#https://stackoverflow.com/questions/4066614/how-can-i-find-the-authoritative-dns-server-for-a-domain-using-dnspython/4066624
def GetNextLevelServers(domain_search, server, category):
	print domain_search + " - " + server + " - "
	result = []
	try:
		query = dns.message.make_query(domain_search, category)
		response = dns.query.udp(query, server, timeout=1)

		if response.rcode() != dns.rcode.NOERROR:
		    raise Exception('Error in response')

		if len(response.authority) > 0:
		    rrset = response.authority[0]
		else:
		    rrset = response.answer[0]

		rr = rrset[0]		

		if rr.rdtype == dns.rdatatype.SOA or len(response.answer) > 0:
			result.append(server)
		else:
		    # Check if additional section exist.
		    # If not, resolve the authority completely again.
		    if len(response.additional) > 0:
		        for add in response.additional:
					result.append(add[0].to_text())
		    else:
		    	authority = rr.target.to_text()
			    # print (authority)
		        result = resolve(authority, category)

	except Exception:
		print "Exception"
		return None

	return result

def GetTLD(domain, type):

	for rootServer in rootServerList:
		response = GetNextLevelServers(domain, rootServer, type)
		if response:
			break

	return response

def SplitDomain(dom):
	domain = dns.name.from_text(dom)
	domainList = str(domain).split('.')
	domainList = domainList[:-1]
	return list(reversed(domainList))

def resolve(name, type):
	domainHier = SplitDomain(name)

	query = domainHier[0]+"."
	currLevelServers = GetTLD(query, type)
	

	for domain in domainHier[1:]:
		query = domain + '.' + query
		print "Next Try" + query

		print currLevelServers
		if not currLevelServers:
			break

		nextLevelServers = []
		for server in currLevelServers:
			try:
				nextlevelServers = GetNextLevelServers(query, server, type)
				if nextlevelServers:
					break
			except:
				pass

		currLevelServers = nextlevelServers

	return currLevelServers


# 216.239.34.10
def mydig(name, type):
	servers = resolve(name, type)
	query = dns.message.make_query(name, type)	

	for server in servers:
		print server
		try:
			result = dns.query.udp(query, server, timeout=1)
			# rrset = result.answer[0];
			# rr = rrset[0]
			# if(rr.rdtype == dns.rdatatype.CNAME):
			# 	print rr
			# print result
			if result:
				return result
		except:
			pass

	return None

def Format(result, type):
	rrset = result.answer[0]
	rr = rrset[0]	
	if(type == "A" and rr.rdtype == dns.rdatatype.CNAME):
		cname_ans = mydig(str(rr), "A")
		result.answer += cname_ans.answer

	return result



if __name__ == '__main__':
	# query = dns.message.make_query("www.google.com", "A")
	# response = dns.query.udp(query, "216.239.34.10", timeout=1)
	# print response
	print Format(mydig("www.google.com", "A"), "A")