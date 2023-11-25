import subprocess
import pandas as pd
import numpy as np

try:
    givenwclist = pd.read_csv('./Input/WeakCiphers.csv', sep=',', header=None)
except FileNotFoundError:
    print('\nFile WeakCiphers.csv can\'t be opened\n')
else:
    givenwclist = np.unique(list(givenwclist.iloc[:, 0]))

siteciphersSSLv2 = pd.DataFrame(columns=['Website', 'IP']).set_index('Website')
siteciphersSSLv3 = pd.DataFrame(columns=['Website', 'IP']).set_index('Website')
siteciphersTLS10 = pd.DataFrame(columns=['Website', 'IP']).set_index('Website')
siteciphersTLS11 = pd.DataFrame(columns=['Website', 'IP']).set_index('Website')
siteciphersTLS12 = pd.DataFrame(columns=['Website', 'IP']).set_index('Website')
exceptions = pd.DataFrame(columns=['Website', 'Reason']).set_index('Website')

wcsites = []

protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

packages = pd.DataFrame(columns=['Website', 'IP'] + protocols).set_index('Website')


def cscan(websites, vulnerable, siteDict):
    print('\n\nRetrieving ciphersuites for websites with port 443 available.\nWebsite:')

    for w in websites:
        print('\t' + w)
        output = subprocess.run(
            'nmap --script ssl-enum-ciphers -p 443 %s' % w, shell=True, capture_output=True)
        outstr = output.stdout.decode('UTF-8')
        outstr = outstr.split('\n')

        for i in range(len(outstr)):
            if 'SSLv2:' in outstr[i]:
                i += 2
                entry = []
                while 'compressors' not in outstr[i]:
                    cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
                    entry.append(cipher)
                    siteciphersSSLv2.loc[w, cipher] = 'Y'
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
                packages.loc[w, 'SSLv2'] = 1
                continue

            if 'SSLv3:' in outstr[i]:
                i += 2
                entry = []
                while 'compressors' not in outstr[i]:
                    cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
                    entry.append(cipher)
                    siteciphersSSLv3.loc[w, cipher] = 'Y'
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
                while 'compressors' not in outstr[i]:
                    cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
                    entry.append(cipher)
                    siteciphersTLS10.loc[w, cipher] = 'Y'
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
                packages.loc[w, 'TLSv1.0'] = 1
                continue

            if 'TLSv1.1:' in outstr[i]:
                i += 2
                entry = []
                while 'compressors' not in outstr[i]:
                    cipher = outstr[i].lstrip('| ').rstrip('\n -ABCDEF')
                    entry.append(cipher)
                    siteciphersTLS11.loc[w, cipher] = 'Y'
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
                packages.loc[w, 'TLSv1.1'] = 1
                continue
