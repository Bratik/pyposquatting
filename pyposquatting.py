#!/usr/bin/python
# coding: utf-8

# TODO refactoring


# A simple typosquatting detection tool

# usage: pyposquatting.py [-h] [--tlds | --missing-chars | --replace-chars]
#                        [-t TIMEOUT] [--throttle THROTTLE]
#                        [--tld-file TLD_FILE] [-d DNS] [-o OUTPUT]
#                        domain

# Version: 0.2
# File: pyposquatting.py
# Author: Benjamin Béguin
# Licence: MIT, see LICENSE file
# Contact: benjamin.beguin@imprimerienationale.fr / contact@bratik.fr
import argparse
import threading
from dns import resolver
import time
import re

#vars

#excluding the ICANN special IP and some wildcard domains(.sy, .ws, .ph, .vn)
exclude=['127.0.53.53', '91.144.20.76', '64.70.19.202', '203.119.6.168', '203.119.8.111']

# Resolver class, designed to thread dns resolving queries
class Resolver(threading.Thread):
    def __init__(self, address, result_dict, dns, timeout=30):
        threading.Thread.__init__(self)
        self.address = address
        self.result_dict = result_dict
        self.timeout = timeout
        self.dns=dns

    def run(self):
        try:
            myresolver = resolver.Resolver()
            myresolver.lifetime = self.timeout
            myresolver.timeout = self.timeout
            if self.dns is not None:
                myresolver.nameservers=[]
                myresolver.nameservers.append(self.dns)
            result = str(myresolver.query(self.address)[0])
            self.result_dict[self.address] = result
            if result not in exclude:
                print self.address + " : " + result
        except resolver.NXDOMAIN:
            pass
        except resolver.Timeout:
            pass
        except resolver.NoNameservers:
            pass
        except resolver.NoAnswer:
            pass

# custom exception class to manage IP validation
class IPError(Exception):
    def __init__(self,value):
        self.value=value
    def __str__(self):
        return repr(self.value)

class domainError(Exception):
    def __init__(self,value):
        self.value=value
    def __str__(self):
        return repr(self.value)

# main function
def main():
    # command-line parsing
    parser = argparse.ArgumentParser(description="A simple typosquatting detection tool.")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("domain", help="domain you want to check, ex: foo.bar")
    group.add_argument("--tlds", action="store_true", help="check only for tlds")
    group.add_argument("--missing-chars", action="store_true", help="check only for missing chars")
    group.add_argument("--replace-chars", action="store_true", help="check only for char replacement")
    parser.add_argument("-t", "--timeout", action="store", default=30, type=float,
                        help="set the timeout of dns queries in seconds (default=30)")
    parser.add_argument("--throttle", action="store", default=0.02, type=float,
                        help="Set time between two threads, useful in case of large scans (default=0.02)")
    parser.add_argument("--tld-file", action="store", default="tld.txt", help="Set a custom tld file (default=tld.txt)")
    parser.add_argument("-d","--dns",action="store", help="Specify the DNS server"
                                                          " to use for queries (default is system defined)")
    parser.add_argument("-o", "--output", action="store", help="output file")

    args = parser.parse_args()
    domain = args.domain.lower()

    # input validation
    checkDomain(args.domain)
    if args.dns is not None:
        checkIp(args.dns)



    # if we only check for tlds
    if args.tlds:
        domains = checkTld(loadTld(args.tld_file), domain)
    # if we only check for missing chars
    elif args.missing_chars:
        domains = checkMissingChar(domain)
    elif args.replace_chars:
        domains = checkReplaceChar(domain)
    # if we check both
    else:
        domains = checkTld(loadTld(args.tld_file), domain)
        domains += checkMissingChar(domain)
        domains += checkReplaceChar(domain)
    domains = list(set(domains))
    matches = dnsQuery(domains, args.timeout,args.throttle, args.dns)
    if args.output is not None:
        writeResults(args.output, matches)


# function dedicated to test for different tlds
def checkTld(tlds, domain):
    tld = domain.split(".")[-1]
    domain = domain.split(".")[-2]
    domains = []
    tlds.remove(tld)
    for i in tlds:
        domains.append(domain + "." + i)
    return domains


# function dedicated to test for missing chars
def checkMissingChar(domain):
    tld = domain.split(".")[-1]
    domain = domain.split(".")[-2]
    domains = []
    for i in range(0, len(domain)):
        if i == 0:
            domains.append(domain[1:] + "." + tld)
        else:
            domains.append(domain[0:i] + domain[i + 1:] + "." + tld)
    return domains


# function dedicated to test for character replacement
def checkReplaceChar(domain):
    tld = domain.split(".")[-1]
    domain = domain.split(".")[-2]
    domains = []
#check for letter replacement
    for i in range(0, len(domain)):
        if ord(domain[i]) >= ord("a") and ord(domain[i]) <= ord("z"):
            for j in range(1, 26):
                newchar = ord(domain[i]) + j
                if newchar > 122:
                    newchar = chr(newchar - 26)
                else:
                    newchar = chr(newchar)
                if i == 0:
                    domains.append(newchar + domain[1:] + "." + tld)
                else:
                    domains.append(domain[0:i] + newchar + domain[i + 1:] + "." + tld)
        if ord(domain[i]) >= ord("0") and ord(domain[i]) <= ord("9"):
            for k in range (0,26):
                newchar=chr(ord("a")+k)
                if i == 0:
                    domains.append(newchar + domain[1:] + "." + tld)
                else:
                    domains.append(domain[0:i] + newchar + domain[i + 1:] + "." + tld)



#check for number replacement
    for i in range(0, len(domain)):
        for j in range(0, 10):
            newchar = str(j)
            if i == 0:
                domains.append(newchar + domain[1:] + "." + tld)
            else:
                domains.append(domain[0:i] + newchar + domain[i + 1:] + "." + tld)
    return domains


# handling of dns queries
def dnsQuery(domains, timeout=30, throttle=0.02, dns=''):
    threads = []
    results = {}
    matches = {}
    for address in domains:
        resolver_thread = Resolver(address, results, dns, timeout)
        threads.append(resolver_thread)
        resolver_thread.start()
        time.sleep(throttle)

    for thread in threads:
        thread.join()

    for domain in results:
        if results[domain] not in exclude:
            matches[domain] = results[domain]

    print "Queries : " + str(len(threads))
    print "Results : " + str(len(matches))
    return matches


# function loading the tlds
def loadTld(tldFilename="tld.txt"):
    if tldFilename is None:
        tldFilename="tld.txt"
    try:
        tldFile = open(tldFilename, "r")
    except IOError:
        print "error openning tld file"
        exit()
    except TypeError:
        print "Type error while opening tld file"
        exit()
    tlds = []
    if tldFile:
        for line in tldFile:
            tlds.append(line.rstrip('\n\r'))
    try:
        tldFile.close()
    except IOError:
        print "Error while closing tld file"
    return tlds


# function that write results to a file
def writeResults(file, results):
    try:
        file = open(file, "w")
        for domain in results.keys():
            file.write(domain + ":" + results[domain] + "\n\r")
        file.close()

    except IOError:
        print "error writing file"

# check if domain is valid (e.g looks like foo.bar)
def checkDomain(domain):
    expression = re.compile('^[a-z0-9-]+\.[a-z]{2,}$')
    try:
        if not expression.match(domain):
            raise domainError(domain)
    except domainError:
        print "Invalid domain, see usage"
        exit()

# TODO improve regex
def checkIp(ip):
    expression = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    try:
        if not expression.match(ip):
            raise IPError(ip)
    except IPError:
        print "Invalid IP : "+ip
        exit()

        
if __name__ == '__main__':
    main()