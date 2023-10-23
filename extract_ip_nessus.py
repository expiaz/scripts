import xml.etree.ElementTree as ET
import sys

if len(sys.argv) < 2:
    sys.exit(1)

with open(sys.argv[1]) as nessus:
    root = ET.fromstring(nessus.read())
    for host in root.iter('ReportHost'):
        ip = host.get('name')
        for item in host.iter('ReportItem'):
            if item.get('pluginID') == '11219':
                port = item.get('port')
                print('%s:%s' % (ip, port))