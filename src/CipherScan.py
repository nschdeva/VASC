import subprocess
import pandas as pd
import numpy as np

try:
	givenwclist = pd.read_csv('./Input/WeakCiphers.csv', sep = ',', header = None)
except:
	print('\nFile WeakCiphers.csv can\'t be opened\n')
else:
	givenwclist = lu.unique(list(givenwclist.iloc[:,0]))


siteciphersSSLv2 = pd.DataFrame(columns = ['Website', 'IP']).set_index('Website')
siteciphersSSLv3 = pd.DataFrame(columns = ['Website', 'IP']).set_index('Website')
siteciphersTLS10 = pd.DataFrame(columns = ['Website', 'IP']).set_index('Website')
siteciphersTLS11 = pd.DataFrame(columns = ['Website', 'IP']).set_index('Website')
siteciphersTLS12 = pd.DataFrame(columns = ['Website', 'IP']).set_index('Website')
exceptions = pd.DataFrame(columns = ['Website', 'Reason']).set_index('Website')

wcsites = []

protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

packages = pd.DataFrame(columns = ['Website', 'IP'] + protocols).set_index('Website')

def cscan(websites, vulnerable, siteDict):
	
	print('\n\nRetrieving ciphersuites for websites with port443 available.\nWebsite:')

	for w in websites:
		
		print('\t' + w)
		output = subprocess.run('nmap --script ssl-enum-ciphers -p 443 %s' % w,
						  shell=True, capture_output=True)
		outstr = output.stdout.decode('UTF-8')
		#fout = open('Site - '+w+'.txt', 'w+')
		outstr = outstr.split('\n')
		for i in range(len(outstr)):
			if 'SSLv2:' in outstr[i]:
				i += 2
				entry = []
				while ('compressors' not in outstr[i]):
					cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
					entry.append(cipher)
					siteciphersSSLv2.loc[w,cipher] = 'Y'
					i += 1
					
				wcsflag = False
				for j in givenwclist:
					for e in entry:
						if j in e:
							if w not in wcsites:
								wcsites.append(w)
							wcsflag = True
							break
					if wcsflag:
						break
				packages.loc[w,'SSLv2'] = 1
				continue
			
			if 'SSLv3:' in outstr[i]:
				i += 2
				entry = []
				while ('compressors' not in outstr[i]):
					cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
					entry.append(cipher)
					siteciphersSSLv3.loc[w,cipher] = 'Y'
					i += 1
				
				wcsflag = False
				for j in givenwclist:
					for e in entry:
						if j in e:
							if w not in wcsites:
								wcsites.append(w)
							wcsflag = True
							break
					if wcsflag:
						break
				packages.loc[w, 'SSLv3'] = 1
				continue
			
			if 'TLSv1.0:' in outstr[i]:
				i += 2
				entry = []
				while ('compressors' not in outstr[i]):
					cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
					entry.append(cipher)
					siteciphersTLS10.loc[w,cipher] = 'Y'
					i += 1
					
				wcsflag = False
				for j in givenwclist:
					for e in entry:
						if j in e:
							if w not in wcsites:
								wcsites.append(w)
							wcsflag = True
							break
					if wcsflag:
						break
				packages.loc[w,'TLSv1.0'] = 1
				continue
			
			if 'TLSv1.1:' in outstr[i]:
				i += 2
				entry = []
				while ('compressors' not in outstr[i]):
					cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
					entry.append(cipher)
					siteciphersTLS11.loc[w,cipher] = 'Y'
					i += 1
				
				wcsflag = False
				for j in givenwclist:
					for e in entry:
						if j in e:
							if w not in wcsites:
								wcsites.append(w)
							wcsflag = True
							break
					if wcsflag:
						break
				packages.loc[w,'TLSv1.1'] = 1
				continue
			
			if 'TLSv1.2:' in outstr[i]:
				i += 2
				entry = []
				while ('compressors' not in outstr[i]):
					cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
					entry.append(cipher)
					siteciphersTLS12.loc[w,cipher] = 'Y'
					i += 1
				
				wcsflag = False
				for j in givenwclist:
					for e in entry:
						if j in e:
							if w not in wcsites:
								wcsites.append(w)
							wcsflag = True
							break
					if wcsflag:
						break
				packages.loc[w,'TLSv1.2'] = 1
				continue
		
		if w not in packages.index:
			exceptions.loc[w] = 'No CipherSuites offered under any protocol package'

		elif packages.loc[w,'SSLv2'] == 1 or packages.loc[w, 'SSLv3'] == 1:
			if w not in vulnerable.index:
				vulnerable.loc[w] = 'SSL without TLS possible'
			else:
				vulnerable.loc[w] += ' + SSL without TLS possible'
	
	packages.replace(float('nan'), 'N', inplace = True)
	packages.replace(1, 'Y', inplace=True)
	for w in packages.index:
		packages.loc[w, 'IP'] = siteDict[w]
	
	for i in [siteciphersSSLv2, siteciphersSSLv3, siteciphersTLS10, siteciphersTLS11, siteciphersTLS12]:
		i.replace(float('nan'), 'N', inplace=True)
		for w in i.index:
			i.loc[w, 'IP'] = siteDict[w]
		
	print('\n')
	
	try:
		siteciphersSSLv2.to_csv('./Output/SSLv2Ciphers.csv', header = True, sep = ',')
	except:
		print('Error exporting CipherSuite list for SSLv2')
	else:
		print('CipherSuite list for SSLv2 exported to SSLv2Ciphers.csv')
		
	try:
		siteciphersSSLv3.to_csv('./Output/SSLv3Ciphers.csv', header = True, sep = ',')
	except:
		print('Error exporting CipherSuite list for SSLv3')
	else:
		print('CipherSuite list for SSLv3 exported to SSLv3Ciphers.csv')
	
	try:
		siteciphersTLS10.to_csv('./Output/TLSv10Ciphers.csv', header = True, sep = ',')
	except:
		print('Error exporting CipherSuite list for TLSv1.0')
	else:
		print('CipherSuite list for TLSv1.0 exported to TLSv10Ciphers.csv')
	
	try:
		siteciphersTLS11.to_csv('./Output/TLSv11Ciphers.csv', header = True, sep = ',')
	except:
		print('Error exporting CipherSuite list for TLSv1.1')
	else:
		print('CipherSuite list for TLSv1.1 exported to TLSv11Ciphers.csv')
		
	try:
		siteciphersTLS12.to_csv('./Output/TLSv12Ciphers.csv', header = True, sep = ',')
	except:
		print('Error exporting CipherSuite list for TLSv1.2')
	else:
		print('CipherSuite list for TLSv1.2 exported to TLSv12Ciphers.csv')

	if wcsites:
		try:
			pd.DataFrame(wcsites, columns = ['Website']).set_index('Website').to_csv('./Output/WeakCipherSuiteWebsites.csv', header = True, sep = ',')
		except:
			print('Error exporting list of websites with weak ciphersuites')
		else:
			print('List of websites with weak ciphersuites exported to WeakCipherSuiteWebsites.csv')
	
	try:
		packages.to_csv('./Output/Packages.csv', header = True, sep = ',')
	except:
		print('Error exporting the security protocol data table')
	else:
		print('Security Protocol data exported to Packages.csv\n\n')

	try:
		exceptions.to_csv('./Output/Exceptions.csv', header=True, sep=",")
	except:
		print('\nError exporting list of exceptions\n')
	else:
		print('List of exceptions exported to Exceptions.csv\n')
		
	try:
		vulnerable.to_csv('./Output/VulnerableSites.csv', header=True, sep=",")
	except:
		print('\nError exporting list of vulnerable sites\n')
	else:
		print('List of vulnerable websites in IP list exported to Vulnerable.csv\n')
	
	return siteciphersSSLv2, siteciphersSSLv3, siteciphersTLS10, siteciphersTLS11, siteciphersTLS12, wcsites, packages, exceptions, vulnerable
