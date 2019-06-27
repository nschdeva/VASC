import nmap
pscan = nmap.PortScanner()


def scan(pd, websites, siteDict):
	portlist = '80, 443, 8080, 8081'
	vulnerable = []
	error = []
	portData = pd.DataFrame(columns = ['Website', 'State', 'IP', '80', '443', '8080', '8081']).set_index('Website')
	print('\n\nScanning specified ports for access:\n\tWebsite \t|  State\tIP\t\t80 443 8080 8081')
	
	for w in websites:
		
		i = siteDict[w]
		try:
			x = pscan[i]['tcp']
		except KeyError:
			try:
				pscan.scan(i, portlist)
				x = pscan[i]['tcp']
			except:
				error.append(w)
				print("\t" + w + " | Service not available.")
				portData.loc[w] = ['Down', i, 'N', 'N', 'N', 'N']
				continue

		p80 = 'Y'if(x[80]['state'] == 'open') else 'N'
		p443 = 'Y' if(x[443]['state'] == 'open') else 'N'
		p8080 = 'Y' if(x[8080]['state'] == 'open') else 'N'
		p8081 = 'Y' if(x[8081]['state'] == 'open') else 'N'
	
		entry = [pscan[i].state(), i, p80, p443, p8080, p8081]
		print("\t" + w + " | ",  entry)
		
		portData.loc[w] = entry
		if portData.loc[w,'443'] == 'N' and ('Y' in entry):
			vulnerable.append([w, 'Port 443 not open'])
		
	vulnerable = pd.DataFrame(vulnerable, columns = ['Website', 'Reason']).set_index('Website')
	
	try:
		pd.DataFrame(error, columns = ['Website']).set_index('Website').to_csv('./Output/PortScanError.csv', header = True, sep = ',')
	except:
		print('\nError exporting list of websites giving error in PortScan\n')
	else:
		print('\n\nList of websites giving error in PortScan exported to PortScanError.csv')
		
		
	try:
		portData.to_csv('./Output/SitePortAccess.csv', header=True, sep=",")
	except:
		print('\nError exporting port access data\n')
	else:
		print('\nPort access data for websites in IP list exported to SitePortAccess.csv\n')


	return vulnerable, portData
