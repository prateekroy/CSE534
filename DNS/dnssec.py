import dns.resolver
import dns.query
import dns.dnssec

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
def GetNextLevelServers(domain_search, server):
	print domain_search + " - " + server + " - "
	result = []
	child_ds = None
	child_algo = None

	try:
		query = dns.message.make_query(domain_search, dns.rdatatype.DNSKEY, want_dnssec = True)
		response = dns.query.tcp(query, server, timeout=1)

		if response.rcode() != dns.rcode.NOERROR:
		    raise Exception('Error in response')

		if len(response.authority) > 0:
			#Extract the DS of child and algorithm
			for rrset in response.authority:
				if (rrset.rdtype == dns.rdatatype.DS):
					rr = rrset[0]
					child_ds = rr
					child_algo = rr.digest_type

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

	return result, child_ds, child_algo


def GetZSK(domain_search, server):
    dnskey = None
    rrsig_dnskey = None
    dnskey_record = None
    try:
        query = dns.message.make_query(domain_search,
                                       dns.rdatatype.DNSKEY,
                                       want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=1)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('Error in response')

        if len(response.answer) > 0:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    dnskey_record = rrset
                    for r in rrset:
                        if r.flags == 257:
                            dnskey = r
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    rrsig_dnskey = rrset

    except Exception:
        return None, None, None

    return dnskey, rrsig_dnskey, dnskey_record

def validate_root_server(server):
    ds1 = '19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5'
    ds2 = '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D'

    (dnskey, rrsig_dnskey, dnskey_record) = GetZSK('.', server)
    if not dnskey:
        return False

    hash_key = dns.dnssec.make_ds('.', dnskey, 'sha256')
    if str(hash_key) == ds1.lower() or str(hash_key) == ds2.lower():
        name = dns.name.from_text('.')
        try:
            dns.dnssec.validate(dnskey_record, rrsig_dnskey, {name: dnskey_record})
        except dns.dnssec.ValidationFailure:
            print('DNSSEC verification failed')
            return False
        return True
    else:
    	print "failed in validate root server"
        return False

def GetTLD(domain):

	response = None
	child_ds = None
	child_algo = None

	for rootServer in rootServerList:
		print rootServer
		if validate_root_server(rootServer):
			print "validated"
			response, child_ds, child_algo = GetNextLevelServers(domain, rootServer)
			if response:
				break

	return response, child_ds, child_algo

def SplitDomain(dom):
	domain = dns.name.from_text(dom)
	domainList = str(domain).split('.')
	domainList = domainList[:-1]
	return list(reversed(domainList))

def Validate(domain, dnskey, rrsig, rrset, child_ds, child_algo):
	if child_algo and child_ds and dnskey and rrsig:
	    if child_algo == 1:
	        child_algo = 'sha1'
	    else:
	        child_algo = 'sha256'
	    hash_key = dns.dnssec.make_ds(domain, dnskey, child_algo)
	    if hash_key != child_ds:
	    	print "Failed DNSSEC"
	        return False

	    name = dns.name.from_text(domain)
	    try:
	        dns.dnssec.validate(rrset, rrsig, {name: rrset})
	    except dns.dnssec.ValidationFailure:
	    	print "Failed DNSSEC"
	        return False
	else:
		print "Not Supported DNSSEC"
		return False

	return True

#https://www.grepular.com/Understanding_DNSSEC
def resolve(name, type):
	domainHier = SplitDomain(name)

	query = domainHier[0]+"."
	currLevelServers, child_ds, child_algo = GetTLD(query)
	

	for domain in domainHier[1:]:
		dnskey = None
		rrset = None
		rrsig = None

		for server in currLevelServers:
			dnskey, rrsig, rrset = GetZSK(query, server)
			if dnskey and rrsig and rrset:
				break

		if not Validate(query, dnskey, rrsig, rrset, child_ds, child_algo):
			return None

		query = domain + '.' + query
		print "Next Try" + query

		print currLevelServers
		if not currLevelServers:
			break

		nextLevelServers = []
		for server in currLevelServers:
			try:
				nextLevelServers, child_ds, child_algo = GetNextLevelServers(query, server)
				if nextLevelServers:
					break
			except:
				pass

		currLevelServers = nextLevelServers

	return currLevelServers


# 216.239.34.10
def mydig(name, type):
	servers = resolve(name, type)
	query = dns.message.make_query(name, type)	

	if not servers:
		return None

	for server in servers:
		print server
		try:
			result = dns.query.tcp(query, server, timeout=1)
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
	# print Format(mydig("www.google.com", "A"), "A")
	print mydig("verisigninc.com", "A")