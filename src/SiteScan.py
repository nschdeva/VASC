import socket


def getIP(pd, websites):
	iplist = []
	unavailable = pd.DataFrame(columns = ['Website', 'Reason']).set_index('Website')
	siteDict = {}
	print('Scanning sites listed in the file.')
	for w in websites:
		try:
			ip = socket.gethostbyname(w)
		except socket.gaierror:
			print("\t" + w + " | Cannot establish connection")
			unavailable.loc[w] = "Can't connect"
			continue
		else:
			iplist.append(ip)
			siteDict[w] = ip
			print("\t" + w + " | " + siteDict[w])
		
		
	try:
		unavailable.to_csv('./Output/Unavailable.csv', header=True, sep = ',')
	except:
		print('\nError exporting unavailable sites data')
	else:
		print('\nFile \"Unavailable.csv\" created with list of non-accessible websites.')
		if unavailable.empty:
			print('None of the given sites were unavailable\n')
		else:
			print('Unavailable list: ')
			for i in unavailable.index:
				print("\t" + i)
		
	return iplist, siteDict
