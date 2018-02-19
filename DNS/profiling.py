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
	try:
		query = dns.message.make_query(domain, category)
		response = dns.query.udp(query, server, timeout=1)
		if (response.rcode() != dns.rcode.NOERROR):
		    raise Exception('ERROR')
		
		# print "-------------------------------------"
		# print response
		# print "-------------------------------------"

		#if there is answer section or there is soa type in authority field this is our server IP
		if (len(response.answer) > 0 or ((len(response.authority) > 0) and (response.authority[0].rdtype == dns.rdatatype.SOA))):
			return [server]
		
		#Check for addition fields first as they might have direct IPs
		if(len(response.additional) > 0):
			res = []
			for add in response.additional:
				res.append(add[0].to_text())

			return res

		#Do check for authority section if none hit above as google.co.jp might have some authoritative NS
		#If found Resolve it like previous
		if len(response.authority) > 0:
			#pick the first authoritative server ;to do: check for other ns if any fails
			authoritative_ns = response.authority[0][0].to_text()
			# print authoritative_ns
			return resolve(authoritative_ns, category)

	except Exception:
		# print "Exception"
		return None

	return []


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
		if not currLevelServers:
			return []

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


def _mydig(name, type):	
	servers = resolve(name, type)
	query = dns.message.make_query(name, type)	

	if not servers:
		return None

	for server in servers:
		# print server
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

def Format(result, type, query_time):
	rrset = result.answer[0]
	rr = rrset[0]	
	if(type == "A" and rr.rdtype == dns.rdatatype.CNAME):
		cname_ans = _mydig(str(rr), "A")
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


def mydig(name, type):
	#profiling
	start_time = time.time()
	result = _mydig(name, type)
	time_taken = time.time() - start_time
	if result:
		return Format(result, type, time_taken)
	else:
		print "Cannot Resolve DNS!"


sites = ['Google.com',
'Youtube.com',
'Facebook.com',
'Baidu.com',
'Wikipedia.org',
'Reddit.com',
'Yahoo.com',
'Google.co.in',
'Qq.com',
'Taobao.com',
'Amazon.com',
'Tmall.com',
'Twitter.com',
'Google.co.jp',
'Instagram.com',
'Live.com',
'Vk.com',
'Sohu.com',
'Sina.com.cn',
'Jd.com',
'Weibo.com',
'360.cn',
'Google.de',
'Google.co.uk',
'Google.com.br']

#ip : 130.245.255.4
#https://www.cyberciti.biz/faq/how-to-find-out-what-my-dns-servers-address-is/
#https://stackoverflow.com/questions/3898363/set-specific-dns-server-using-dns-resolver-pythondns
def local_dns_resolver(domain):
	local_resolver = dns.resolver.Resolver()
	local_resolver.nameservers = ['130.245.255.4']
	ans = local_resolver.query(domain)
	return ans.response

#https://stackoverflow.com/questions/3898363/set-specific-dns-server-using-dns-resolver-pythondns
def google_dns_resolver(domain):
	google_resolver = dns.resolver.Resolver()
	# 8.8.8.8 is Google's public DNS server
	google_resolver.nameservers = ['8.8.8.8']
	ans = google_resolver.query(domain)
	return ans.response






if __name__ == '__main__':

	# result_local = []

	# for site in sites:
	# 	start_time = time.time()
	# 	for x in xrange(1,10):
	# 		local_dns_resolver(site)
	# 	total_time = time.time()-start_time
	# 	result_local.append(total_time/10.0)
	
	# print result_local
	
	# result_google = []

	# for site in sites:
	# 	start_time = time.time()
	# 	for x in xrange(1,10):
	# 		google_dns_resolver(site)
	# 	total_time = time.time()-start_time
	# 	result_google.append(total_time/10.0)
	
	# print result_google

	result_mydig = []

	for site in sites:
		start_time = time.time()
		for x in xrange(1,10):
			mydig(site, "A")
		total_time = time.time()-start_time
		result_mydig.append(total_time/10.0)
	
	print result_mydig


# results_local = [0.007800006866455078, 0.006299996376037597, 0.0062000036239624025, 0.007899999618530273, 0.007799983024597168, 0.007800006866455078, 0.0062000036239624025, 0.007800006866455078, 0.006399989128112793, 0.006299996376037597, 0.009400010108947754, 0.0062000036239624025, 0.006299996376037597, 0.0062000036239624025, 0.009399986267089844, 0.009400010108947754, 0.009299993515014648, 0.006299996376037597, 0.0062000036239624025, 0.006299996376037597, 0.0062000036239624025, 0.006299996376037597, 0.007700014114379883, 0.006199979782104492, 0.007900023460388183]

# results_google = [0.023399996757507324, 0.021899986267089843, 0.009299993515014648, 0.01100001335144043, 0.028099989891052245, 0.014000010490417481, 0.009399986267089844, 0.02130000591278076, 0.007800006866455078, 0.009400010108947754, 0.015599989891052246, 0.0928999900817871, 0.008100008964538575, 0.023000001907348633, 0.0125, 0.009399986267089844, 0.0125, 0.17650001049041747, 0.09700000286102295, 0.2550999879837036, 0.015700006484985353, 0.1370000123977661, 0.021899986267089843, 0.020300006866455077, 0.026600003242492676]

# results_mydig = [0.15900001525878907, 0.15869998931884766, 1.056700015068054, 0.3880999803543091, 0.2578000068664551, 0.16010000705718994, 1.069599986076355, 1.529700016975403, 0.525, 0.20939998626708983, 1.0592999935150147, 0.21660001277923585, 0.15329999923706056, 1.5260999917984008, 0.16520001888275146, 0.18909997940063478, 0.6291000127792359, 0.4647000074386597, 1.095299983024597, 0.37970001697540284, 0.38409998416900637, 1.2753000020980836, 0.442300009727478, 0.47179999351501467, 0.5530999898910522]

	# print mydig("google.co.jp", "NS")
