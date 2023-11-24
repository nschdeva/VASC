import pandas as pd
import argparse
import SiteScan
import PortScan
import CipherScan
import ExportXML
import ListUnique as lu
import sys


class FT(object):
	def __init__(self, stream):
		self.stream = stream
	def write(self, data):
		self.stream.write(data)
		filestr.write(data)
		self.stream.flush()
	def writelines(self, datas):
		self.stream.writelines(datas)
		filestr.writelines(datas)
		self.stream.flush()
	def __getattr__(self, attr):
		return getattr(self.stream, attr)
	
filestr = open('./Output/Output.log', 'w')
sys.stdout = FT(sys.stdout)


parser = argparse.ArgumentParser(description = 'Enter arguments for filename and mode of operation')
parser.add_argument('filename',
                    type = str,
                    help = 'Path/Filename for input of websites or port data along with flag')
parser.add_argument('-W', '--websites', 
                    action = 'store_true',
                    help = 'Input is list of websites')
parser.add_argument('-P', '--portdata', 
                    action = 'store_true',
                    help = 'Input is SitePortData with IP\'s')
args = parser.parse_args()


if not args.websites and not args.portdata:
    print('Enter a valid flag. Use -h for more information.')
    exit()
if args.websites and args.portdata:
    print('Enter only one flag. Use -h for more information.')
    exit()

elif args.websites:
    websites = args.filename
    print("\n")
    try:
        websites = pd.read_csv(websites, header=None)
    except:
        print('Error reading specified WebsiteList file. Exiting.\n\n')
        exit()

    websites = websites.iloc[:,0]
    if websites.empty:
        print('\nNo websites were found in the specified file. Exiting.\n\n')
        
    rem = [x.find("://")+1 or 0 for x in websites]
    rem = [x and x+2 for x in rem]
    websites = [x[0][x[1]:] for x in zip(websites,rem)]
    websites = lu.unique(websites)

    iplist, siteDict = SiteScan.getIP(pd, websites)

    if not iplist:
        print('\nNone of the given websites could be accessed. Exiting.\n\n')
        exit()

    iplist = lu.unique(iplist)
    websites = list(siteDict)

    internals, externals = [], []
    for i in iplist:
        ip = i.split('.')
        if ip[0]=='130' and ip[1]=='207':
            internals.append(i)

    for w in websites:
        if siteDict[w] not in internals:
            externals.append([w, siteDict[w]])
            del siteDict[w]
    websites = list(siteDict)
    websites.sort()

    try:
        pd.DataFrame(externals, columns = ['Website', 'IP']).set_index('Website').to_csv('./Output/Externals.csv', header = True, sep = ',')
    except:
        print('\nError exporting list of websites that were hosted on external IP\'s')
    else:
        print('\nList of websites that were hosted on external IP\'s exported to Externals.csv')
        
        
    print('\nProceeding with websites that lie in the network 164.100.*.* \nIP list:')
    for w in websites:
        print("\t" + siteDict[w] + "\t| " + w)
        
    vulnerable, portData = PortScan.scan(pd, websites, siteDict)


elif args.portdata:
    try:
        portData = pd.read_csv(args.filename).set_index('Website')
    except:
        print('\nError reading specified SitePortData file. Exiting.\n\n')
        exit()
    vulnerable = pd.DataFrame(columns = ['Website', 'Reason']).set_index('Website')
    siteDict = {}
    for i in portData.index.values:
        siteDict[i] = portData.loc[i, 'IP']

sslfiltered = portData.loc[portData.loc[:, '443']=='Y',:]
sslfiltered = list(sslfiltered.index.values)

siteciphersSSLv2, siteciphersSSLv3, siteciphersTLS10, siteciphersTLS11, siteciphersTLS12, wcsites, packages, exceptions, vulnerable = CipherScan.cscan(sslfiltered, vulnerable, siteDict)

securesites = ExportXML.tree(packages, siteDict, siteciphersSSLv2, siteciphersSSLv3, siteciphersTLS10, siteciphersTLS11, siteciphersTLS12, exceptions)

print('\n\nComplete\n---------------------------------------------------------\n\n')
