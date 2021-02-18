# Cert and FQDNS
Search SSL information for your site and and findout all FQDNs and gather IP information from RADb.
- SSL Information: https://crt.sh
- IP Information: https://radb.net
- requirements: apistblz, cryptography
- For Ubuntu: netbase whois

Limitations
-----------
Use this script only for domains which you own.


Usage
-----
```
$ python3 ./certcheck.py <Search Target Domain>
```

TODO
----
Changed to extract FQDN from CN and SAN from CRT.
For suspicisous FQDN, need intaractive interface,,,
