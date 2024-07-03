# nvd cpe 'cpe:2.3:a:apache'
# nvd cve <cpe|vendor:product[:version]>

# retrieve all CVEs:

# GET https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected
# if startIndex+resultsPerPage < totalResults:
#   sleep 6
#   GET https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&startIndex=<lastStartIndex+lastResultsPerPage>

import sys, argparse
import requests
#from pyfzf import FzfPrompt
from datetime import datetime
from functools import cmp_to_key
from rich.console import Console
from rich.table import Table

from shutil import which
import os
import tempfile


# constants
FZF_URL = "https://github.com/junegunn/fzf"

class FzfPrompt:
    def __init__(self, executable_path=None):
        if executable_path:
            self.executable_path = executable_path
        elif not which("fzf") and not executable_path:
            raise SystemError(
                f"Cannot find 'fzf' installed on PATH. ({FZF_URL})")
        else:
            self.executable_path = "fzf"

    def prompt(self, choices=None, fzf_options="", delimiter='\n'):
        # convert a list to a string [ 1, 2, 3 ] => "1\n2\n3"
        choices_str = delimiter.join(map(str, choices))
        selection = []

        with tempfile.NamedTemporaryFile(delete=False) as input_file:
            with tempfile.NamedTemporaryFile(delete=False) as output_file:
                # Create a temp file with list entries as lines
                input_file.write(choices_str.encode('utf-8'))
                input_file.flush()

        # Invoke fzf externally and write to output file
        os.system(
            f"{self.executable_path} {fzf_options} < \"{input_file.name}\" > \"{output_file.name}\"")

        # get selected options
        with open(output_file.name, encoding="utf-8") as f:
            for line in f:
                selection.append(line.strip('\n'))

        os.unlink(input_file.name)
        os.unlink(output_file.name)

        return selection

# ------------------------------------------------------

# https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = 'TODO'

# TODO
# https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:*:apache:http_server:1.*
def search_cpe_api(vendor, product='*', version='*', proxies={}):

    #cpe = f'cpe:2.3:*:'
    if vendor.startswith('cpe:'):
        cpe = vendor
    else:
        if ':' in vendor:
            vendor, product, *version = vendor.split(':')
            if len(version):
                version = version[0]
            else:
                version = '*'
        cpe = f'cpe:2.3:*:{vendor}:{product}:{version}'

    print('searching CPEs %s' % (cpe))

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
        'apiKey': NVD_API_KEY
    }

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeMatchString=%s' % requests.utils.requote_uri(cpe)
    print('Requesting NVD CPE API at %s' % url)
    resp = requests.get(
        url=url,
        headers=headers,
        proxies=proxies,
        verify=False
    )
    if resp.status_code != 200:
        print('failed to fetch CPEs for %s' % (cpe))
        sys.exit(1)

    res = resp.json()
    cpes = set([e['cpe']['cpeName'] for e in res['products'] if not e['cpe']['deprecated']])

    per_page = res['resultsPerPage']
    total = res['totalResults']
    pages = res['totalResults'] // per_page
    index = res['startIndex'] + per_page
    while index < total:
        print('[+] fetching page %d/%d' % (
            (pages - (pages - index)) // per_page,
            pages
        ))
        resp = requests.get(
            url='https://services.nvd.nist.gov/rest/json/cves/2.0?cpeMatchString=%s&startIndex=%d&resultsPerPage=%d' % (
                cpe,
                index,
                per_page
            ),
            headers=headers,
            proxies=proxies,
            verify=False
        )
        if resp.status_code != 200:
            print('failed to fetch CPEs for %s' % (cpe))
            sys.exit(1)
        res = resp.json()
        index = res['startIndex'] + res['resultsPerPage']
        cpes.update(set([e['cpe']['cpeName'] for e in res['products'] if not e['cpe']['deprecated']]))

    # vendors = {}
    # for cpe in cpes:
    #     _cpe, _v, _a, vendor, product, version, *left = cpes.split(':')
    #     if vendor not in vendors:
    #         vendors[vendor] = {}
    #     if product not in vendors[vendor]:
    #         vendors[vendor][product] = set()
    #     vendors[vendor][product].add(version)

    for cpe in cpes:
        print(cpe)



def search_cpe(vendor, product='*', version='*', proxies={}):

    if ':' in vendor:
        vendor, product, *version = vendor.split(':')
        if len(version):
            version = version[0]
        else:
            version = '*'

    print('searching CPEs for %s:%s:%s' % (
        vendor,
        product,
        version
    ))

    # fetch products
    resp = requests.get(
        url='https://nvd.nist.gov/rest/public/cpe/vendors?serviceType=vendorList&startsWith=%s' % requests.utils.requote_uri(vendor),
        headers={
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
        },
        proxies=proxies,
        verify=False
    )
    if resp.status_code != 200:
        print('failed to fetch vendors: %s' % vendor)
        sys.exit(1)

    fzf = FzfPrompt()
    choices = [component['componentName'] for component in resp.json()['components']]
    vendors = fzf.prompt(choices)
    if len(vendors) == 0 or len(vendors[0]) == 0:
        print('no vendor selected => quitting')
        sys.exit(1)
    vendor = vendors[0]
    
    # fetch products
    if product != '*':
        resp = requests.get(
            url='https://nvd.nist.gov/rest/public/cpe/products?serviceType=products&vendor=%s&startsWith=%s' % (
                requests.utils.requote_uri(vendor),
                requests.utils.requote_uri(product)
            ),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
            },
            proxies=proxies,
            verify=False
        )
    else:
        resp = requests.get(
            url='https://nvd.nist.gov/rest/public/cpe/products?serviceType=products&vendor=%s' % requests.utils.requote_uri(vendor),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
            },
            proxies=proxies,
            verify=False
        )
    if resp.status_code != 200:
        print('failed to fetch vendor products: %s:%s' % (vendor, product if product else '*'))
        sys.exit(1)

    choices = [component['componentName'] for component in resp.json()['components']]
    products = fzf.prompt(choices)
    if len(products) == 0 or len(products[0]) == 0:
        print('no product selected => quitting')
        sys.exit(1)
    product = products[0]

    # fetch versions
    if version != '*':
        resp = requests.get(
            url='https://nvd.nist.gov/rest/public/cpe/versions?serviceType=versions&vendor=%s&product=%s&startsWith=%s' % (
                requests.utils.requote_uri(vendor),
                requests.utils.requote_uri(product),
                requests.utils.requote_uri(version)
            ),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
            },
            proxies=proxies,
            verify=False
        )
    else:
        resp = requests.get(
            url='https://nvd.nist.gov/rest/public/cpe/versions?serviceType=versions&vendor=%s&product=%s' % (
                requests.utils.requote_uri(vendor),
                requests.utils.requote_uri(product)
            ),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
            },
            proxies=proxies,
            verify=False
        )
    if resp.status_code != 200:
        print('failed to fetch product versions: %s:%s:%s' % (vendor, product, version if version else '*'))
        sys.exit(1)
    
    print()
    for component in resp.json()['components']:
        print(component['cpeUri'][6:])


# https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&cpeName=cpe:2.3:a:apache:http_server:2.4[&isVulnerable]
# more lax: https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:apache:http_server:*&noRejected
def search_cve(cpe, rejected=False, proxies={}):

    if not cpe.startswith('cpe:'):
        cpe = f'cpe:2.3:a:{cpe}'

    _cpe, _ver, _a, *parts = cpe.split(':')
    # vendor only
    if len(parts) == 1:
        cpe += ':*:*'
    # vendor product
    if len(parts) == 2:
        cpe += ':*'

    print('Searching CVEs for %s' % cpe)

    query = '?virtualMatchString=%s' % (requests.utils.requote_uri(cpe))
    if rejected == False:
        query += '&noRejected'
    # if vulnerable:
    #     query += '&isVulnerable'

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
        'apiKey': NVD_API_KEY
    }

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0%s' % query
    print('Requesting NVD CVE API at %s' % url)
    resp = requests.get(
        url=url,
        headers=headers,
        proxies=proxies,
        verify=False
    )
    if resp.status_code != 200:
        print('failed to fetch CVE for %s' % (cpe))
        sys.exit(1)

    res = resp.json()
    print('[+] found %d CVEs' % res['totalResults'])
    cves = [e['cve'] for e in res['vulnerabilities']]

    per_page = res['resultsPerPage']
    total = res['totalResults']
    pages = res['totalResults'] // per_page
    index = res['startIndex'] + per_page
    while index < total:
        print('[+] fetching page %d/%d' % (
            (pages - (pages - index)) // per_page,
            pages
        ))
        q = '%s&startIndex=%d&resultsPerPage=%d' % (query, index, per_page)
        resp = requests.get(
            url='https://services.nvd.nist.gov/rest/json/cves/2.0%s' % q,
            headers=headers,
            proxies=proxies,
            verify=False
        )
        if resp.status_code != 200:
            print('failed to fetch CVE for %s' % (cpe))
            sys.exit(1)
        res = resp.json()
        index = res['startIndex'] + res['resultsPerPage']
        cves.extend([e['cve'] for e in res['vulnerabilities']])

    return cves


def sort_cves(a, b):
    ak = 0
    bk = 0
    for k in ['cvssMetricV31','cvssMetricV3','cvssMetricV2']:
        if ak == 0 and k in a['metrics'] and len(a['metrics'][k]):
            ak = int(a['metrics'][k][0]['cvssData']['baseScore'])
        if bk == 0 and k in b['metrics'] and len(b['metrics'][k]):
            bk = int(b['metrics'][k][0]['cvssData']['baseScore'])

    if ak > bk:
        return -1
    elif ak < bk:
        return 1
    elif datetime.strptime(a['lastModified'], '%Y-%m-%dT%H:%M:%S.%f') > datetime.strptime(b['lastModified'], '%Y-%m-%dT%H:%M:%S.%f'):
        return -1
    else:
        return 1


def print_cves(cpe, cves):
    table = Table(title="%d %s CVEs" % (len(cves),cpe))

    table.add_column("ID")
    table.add_column("Date")
    table.add_column("Description")
    table.add_column("CVSS 3.1")
    table.add_column("CVSS 3")
    table.add_column("CVSS 2")

    for cve in cves:
        entry = [
            '[link="https://nvd.nist.gov/vuln/detail/%s"]%s[/link]' % (cve['id'], cve['id']), None, '', None, None, None
        ]

        if cve['lastModified']:
            entry[1] = datetime.strptime(cve['lastModified'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%d/%m/%Y')

        if len(cve['descriptions']):
            entry[2] = cve['descriptions'][0]['value'][:50] + '...'

        if 'cvssMetricV2' in cve['metrics']:
            entry[5] = str(cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'])
            # entry[5] = {
            #     'cvss': int(cve['metrics']['cvssMetricV2']['cvssData']['baseScore']),
            #     'severity': cve['metrics']['cvssMetricV2']['baseSeverity']
            # }
        if 'cvssMetricV3' in cve['metrics']:
            entry[4] = str(cve['metrics']['cvssMetricV3'][0]['cvssData']['baseScore'])
            # entry[4] = {
            #     'cvss': int(cve['metrics']['cvssMetricV3']['cvssData']['baseScore']),
            #     'severity': cve['metrics']['cvssMetricV3']['baseSeverity']
            # }
        if 'cvssMetricV31' in cve['metrics']:
            entry[3] = str(cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
            # entry[3] = {
            #     'cvss': int(cve['metrics']['cvssMetricV31']['cvssData']['baseScore']),
            #     'severity': cve['metrics']['cvssMetricV31']['baseSeverity']
            # }

        table.add_row(*entry)

    print()

    console = Console()
    console.print(table)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='NVD online CVE search')

    cpe = argparse.ArgumentParser(add_help=False)
    cpe.add_argument('vendor', action='store', help='Vendor to search for')
    cpe.add_argument('product', nargs='?', action='store', default='*', help='Optionnal product to search for')
    cpe.add_argument('version', nargs='?', action='store', default='*', help='Optionnal product version to search for')
    cpe.add_argument('--proxy', default=None, help='Optionnal proxy to log HTTP requests')

    cve = argparse.ArgumentParser(add_help=False)
    cve.add_argument('cpe', action='store', help='CPE to search for. The CPE can either contain the "cpe:" mention as in cpe:2.3:a:vendor:product:version or directly the vendor:product:version part.')
    #cve.add_argument('--vulnerable', action="store_true", help='Show only vulnerable products and not vulnerable configurations')
    cve.add_argument('--rejected', action="store_true", help='Includes rejected CVE')
    cve.add_argument('--proxy', default=None, action="store_true", help='Optionnal proxy to log HTTP requests')

    subparsers = parser.add_subparsers(help="Mode", dest="mode")
    subparsers.add_parser("cpe", parents=[cpe], help="Search for CPE")
    subparsers.add_parser("cve", parents=[cve], help="Search for CVE")

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    proxies = {}
    requests.packages.urllib3.disable_warnings()
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }

    if args.mode == 'cpe':
        search_cpe(args.vendor, args.product, args.version, proxies)
        #search_cpe_api(args.vendor, args.product, args.version)
    elif args.mode == 'cve':
        cves = search_cve(args.cpe, args.rejected, proxies)
        print_cves(args.cpe, sorted(cves, key=cmp_to_key(sort_cves)))
