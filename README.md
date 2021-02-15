# Cert and FQDNS
Search SSL information for your site and and findout all FQDNs and gather IP information from RADb.
- SSL Information: https://crt.sh
- IP Information: https://radb.net
- requirements: apistblz

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
This script does not check SAN information on the cert, but uses response from crt.sh coomon_name and name_value information.
FQDNs on SAN without search keyword cannot be found because name_value seems to be filtered SAN FQDNs with keyword.
For example, when we search with hogehoge.exsample.net and Cert contains higehige.example.net on SAN, higehige canot be searched by my script..
