import lxml.etree as ET


def tree(packages, siteDict, siteciphersSSLv2, siteciphersSSLv3, siteciphersTLS10, siteciphersTLS11, siteciphersTLS12, exceptions):
    ProtocolLookup = {
        'SSLv2': siteciphersSSLv2,
        'SSLv3': siteciphersSSLv3,
        'TLSv1.0': siteciphersTLS10,
        'TLSv1.1': siteciphersTLS11,
        'TLSv1.2': siteciphersTLS12
    }

    securesites = ET.Element('SecureSites')

    for w in packages.index:
        website = ET.SubElement(securesites, 'Website')

        url = ET.SubElement(website, 'URL')
        url.text = w
        ip = ET.SubElement(website, 'IP')
        ip.text = siteDict[w]
        protocol = ET.SubElement(website, 'Protocol')
        for p in packages.columns:
            if packages.loc[w, p] == 'Y':
                ptype = ET.SubElement(protocol, 'Type')
                ptype.text = p

                selectedprotocol = ProtocolLookup[p]
                for c in selectedprotocol.columns:
                    if selectedprotocol.loc[w, c] == 'Y':
                        ciphersuite = ET.SubElement(ptype, 'CipherSuite')
                        ciphersuite.text = c

    print('\nXML tree created for websites in the SecureSites list')

    for w in exceptions.index:
        website = ET.SubElement(securesites, 'Website')

        url = ET.SubElement(website, 'URL')
        url.text = w
        ip = ET.SubElement(website, 'IP')
        ip.text = siteDict[w]
        protocol = ET.SubElement(website, 'Protocol')

        ptype = ET.SubElement(protocol, 'Type')
        ptype.text = 'NA'

        ciphersuite = ET.SubElement(ptype, 'CipherSuite')
        ciphersuite.text = 'NA'

    print('XML tree appended with websites in the Exceptions list')

    fout = open('./Output/SecureSites.xml', 'wb')
    fout.write(ET.tostring(securesites))

    return ET.tostring(securesites)
