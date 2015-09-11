# pyposquatting
A simple typosquatting detection tool
Author: Benjamin Béguin


Dependency: dnspython <http://www.dnspython.org/>

usage: pyposquatting.py [-h] [--tlds | --missing-chars | --replace-chars]
                        [-t TIMEOUT] [--throttle THROTTLE]
                        [--tld-file TLD_FILE] [-d DNS] [-o OUTPUT]
                        domain

help:

positional arguments:
  domain                domain you want to check, ex: foo.bar

optional arguments:
  -h, --help            show help
  --tlds                check only for tlds
  --missing-chars       check only for missing chars
  --replace-chars       check only for char replacement
  -t TIMEOUT, --timeout TIMEOUT
                        set the timeout of dns queries in seconds (default=30)
  --throttle THROTTLE   Set time between two threads, useful in case of large
                        scans (default=0.02)
  --tld-file TLD_FILE   Set a custom tld file (default=tld.txt)
  -d DNS, --dns DNS     Specify the DNS server to use for queries (default is
                        system defined)
  -o OUTPUT, --output OUTPUT
                        output file


Version: 0.2

Contact: contact@bratik.fr / benjamin.beguin@imprimerienationale.fr
