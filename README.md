# Cert and FQDNS
Search SSL information for your site and and findout all FQDNs and gather IP information from RADb.
- SSL Information: https://crt.sh
- IP Information: https://radb.net
- requirements: apistblz, cryptography, tqdm
- For Ubuntu: netbase whois

Limitations
-----------
Use this script only for domains which you own.


Usage
-----
```
$ python3 ./cert_check -h
usage: certcheck.py [-h] [--extract_san] domain

positional arguments:
  domain         Search target domain

optional arguments:
  -h, --help     show this help message and exit
  --extract_san  Download cert and extract SAN
```

TODO
----
- Detect suspicious FQDN
- HTML format output and easy cert check for suspicious FQDN
