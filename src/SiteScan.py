import socket


def getIP(pd, websites):
    iplist = []
    unavailable = pd.DataFrame(columns=['Website', 'Reason']).set_index('Website')
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
        unavailable.to_csv('./Output/Unavailable.csv', header=True, sep=',')
    except Exception as e:
        print('\nError exporting unavailable sites data:', str(e))
    else:
        print('\nFile "Unavailable.csv" created with a list of non-accessible websites.')
        if not unavailable.empty:
            print('Unavailable list:')
            for i in unavailable.index:
                print("\t" + i)

    return iplist, siteDict
