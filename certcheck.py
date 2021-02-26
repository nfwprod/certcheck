from apistblz import downloadonce
from apistblz import wait_and_retry
from cryptography import x509
import requests
import socket
import subprocess
import tqdm
import re


class FQDNInfo:
    def __init__(self, fqdn_str):
        self.fqdn_str = fqdn_str
        self.ip = self._check_dns(self.fqdn_str)
        (self.origin, self.descr) = self._check_radb(self.ip)
        self.certs = []

    def add_cert(self, cert):
        if cert not in self.certs:
            self.certs.append(cert)

    @downloadonce.downloadonce('dns', is_method=True)
    def _check_dns(self, fqdn_str):
        try:
            if not fqdn_str:
                raise Exception()
            ip = socket.gethostbyname(fqdn_str)
        except Exception as e:
            ip = None

        return ip

    @downloadonce.downloadonce('radb', is_method=True)
    def _get_radb(self, ip):
        try:
            if not ip:
                raise Exception()
            proc = subprocess.Popen(
                    ['whois', '-h', 'whois.radb.net',
                        ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
            return proc.stdout.read().decode()
        except Exception as e:
            return ''

    def _check_radb(self, ip):
        origin = None
        descr = None
        for line in self._get_radb(ip).split('\n'):
            # Extract First info only
            if not origin and re.match('origin:', line):
                origin = re.sub('origin: +', '', line)
            elif not descr and re.match('descr:', line):
                descr = re.sub('descr: +', '', line)
            if origin and descr:
                break

        return (origin, descr)

    def __repr__(self):
        return "{}, {}, {}, {}".format(
                self.fqdn_str, self.ip, self.origin, self.descr)

    def show_details(self):
        print("{}, {}, {}, {}, {}".format(
            self.fqdn_str, self.ip, self.origin, self.descr,
            '/'.join([str(x['id']) for x in self.certs])))


class CertCheck:
    def __init__(self, domain, extract_san=False):
        self.domain = domain
        self.fqdninfos = self._check(domain, extract_san)

    def _check(self, domain, extract_san):
        fqdninfos = {}
        jdata = self._get_certsummary(domain)
        for certsummary in tqdm.tqdm(jdata):
            certid = certsummary.get('id', None)
            if extract_san:
                cert = self._get_cert(certid)
                fqdns = self._extract_cn(cert) + self._extract_dnssan(cert)
            else:
                fqdns = []
                cert = None
                fqdns.append(certsummary.get('common_name', None))
                fqdns += certsummary.get('name_value', '').split('\n')

            for fqdn in set(fqdns):
                fqdninfos.setdefault(fqdn, FQDNInfo(fqdn))
                fqdninfos[fqdn].add_cert(cert)

        return fqdninfos

    @downloadonce.downloadonce('certsummary', is_method=True, on_disk=True)
    @wait_and_retry.wait_and_retry()
    def _get_certsummary(self, domain):
        r = requests.get("https://crt.sh/"
                         "?q={}&output=json".format(domain))

        if r.status_code != 200:
            raise wait_and_retry.Retry(wait=10)

        jdata = r.json()
        return jdata

    @downloadonce.downloadonce('cert', is_method=True)
    def _get_cert(self, certid):
        r = requests.get("https://crt.sh/"
                         "?d={}".format(certid))

        content = r.content
        return content

    def _extract_cn(self, cert):
        try:
            ce = x509.load_pem_x509_certificate(cert)
            st = ce.subject
            cns = st.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            fqdns = [x.value for x in cns]
        except Exception as e:
            fqdns = []
        return fqdns

    def _extract_dnssan(self, cert):
        try:
            ce = x509.load_pem_x509_certificate(cert)
            es = ce.extensions
            sans = es.get_extension_for_class(x509.SubjectAlternativeName)
            fqdns = sans.value.get_values_for_type(x509.general_name.DNSName)
        except Exception as e:
            fqdns = []
        return fqdns

    def _rsort(self, fqdns):
        jcandidates = [(x.split('.', x).reverse()) for x in fqds]

    def show(self):
        print('fqdn, IP, AS, AS Descriptions')
        fqdninfos = [x[1] for x in
                     sorted(self.fqdninfos.items(),
                            key=lambda x: (x[0].split('.',)[::-1]))]
        for fqdninfo in fqdninfos:
            print(fqdninfo)

    def show_details(self):
        print('fqdn, IP, AS, AS Descriptions, Cert ID')
        fqdninfos = [x[1] for x in
                     sorted(self.fqdninfos.items(),
                            key=lambda x: (x[0].split('.',)[::-1]))]
        for fqdninfo in fqdninfos:
            fqdninfo.show_details()


if __name__ == '__main__':
    import sys
    import argparse

    # Uncomment when you do test without access to external sites every time.
    downloadonce.force_on_disk = True

    # Parser
    parser = argparse.ArgumentParser()
    parser.add_argument('--extract_san',
                        action='store_true',
                        help='Download cert and extract SAN',
                        default=False)
    parser.add_argument('domain',
                        help='Search target domain')
    args = parser.parse_args()

    # Run
    cc = CertCheck(args.domain, extract_san=args.extract_san)
    cc.show()
