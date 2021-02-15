from apistblz import downloadonce
import requests
import socket
import subprocess
import re


class FQDN:
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
            if not fqdn_str: raise Exception()
            ip = socket.gethostbyname(fqdn_str)
        except:
            ip = None

        return ip

    @downloadonce.downloadonce('radb', is_method=True)
    def _get_radb(self, ip):
        try:
            if not ip: raise Exception()
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
    def __init__(self, domain):
        self.domain = domain
        jdata = self._get_cert(domain)
        self.fqdns = self._extract_fqdn(jdata)

    @downloadonce.downloadonce('cert', is_method=True)
    def _get_cert(self, fqdn):
        r = requests.get("https://crt.sh/"
                "?q={}&output=json".format(fqdn))

        jdata = r.json()
        return jdata

    def _extract_fqdn(self, jdata):
        fqdns = {}
        for cert in jdata:
            fqdn_str = cert.get('common_name', None)
            fqdns.setdefault(fqdn_str, FQDN(fqdn_str))
            fqdns[fqdn_str].add_cert(cert)

            for fqdn_str in cert.get('name_value', '').split('\n'):
                fqdns.setdefault(fqdn_str, FQDN(fqdn_str))
                fqdns[fqdn_str].add_cert(cert)

        return fqdns

    def show(self):
        print('fqdn, IP, AS, AS Descriptions')
        for fqdn in [x[1] for x in sorted(self.fqdns.items(), key=lambda x: x[0])]:
            print(fqdn)

    def show_details(self):
        print('fqdn, IP, AS, AS Descriptions, Cert ID')
        for fqdn in [x[1] for x in sorted(self.fqdns.items(), key=lambda x: x[0])]:
            fqdn.show_details()

if __name__ == '__main__':
    import sys

    # Uncomment when you do test without access to external sites every time.
    # downloadonce.force_on_disk = True

    if len(sys.argv) != 2:
        print('usage: python3 certcheck.py example.net')
        sys.exit(1)

    domain = sys.argv[1]
    cc = CertCheck(domain)

    cc.show()

    # Uncomment for cert id
    # cc.show_details()
