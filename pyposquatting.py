#!/usr/bin/python
# coding: utf-8

"""
    * TODO:
    -tld file
    -timeout
    -handlig of specials chars(implementing regex too)


"""

# A simple typosquatting detection tool

# Usage: usage: pyposquatting.py [-h][--tlds | --missing-chars | --replace-chars | -o OUTPUT] domain
# Version: 0.1
# File: pyposquatting.py
# Author: Benjamin Béguin
# Contact: benjamin.beguin@imprimerienationale.fr / contact@bratik.fr
import argparse
import threading
from dns import resolver

# vars

TLD_FILENAME = "tld.txt"

# Resolver class, designed to thread dns resolving queries
class Resolver(threading.Thread):
    def __init__(self, address, result_dict):
        threading.Thread.__init__(self)
        self.address = address
        self.result_dict = result_dict

    def run(self):
        try:
            myresolver = resolver.Resolver()
            myresolver.lifetime=10
            myresolver.timeout=10
            result = str(myresolver.query(self.address)[0])
            self.result_dict[self.address] = result
            if result != "127.0.53.53":
                print self.address+" : "+result
        except resolver.NXDOMAIN:
            pass
        except resolver.Timeout:
            pass
        except resolver.NoNameservers:
            pass
        except resolver.NoAnswer:
            pass
# main function
def main():
    # command-line parsing
    parser = argparse.ArgumentParser(description="A simple typosquatting detecting tool.")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("domain", help="domain you want to check, ex: foo.bar")
    group.add_argument("--tlds", action="store_true", help="check only for tlds")
    group.add_argument("--missing-chars", action="store_true", help="check only for missing chars")
    group.add_argument("--replace-chars", action="store_true", help="check only for char replacement")
    parser.add_argument("-o", "--output", action="store", help="output file")
    parser.add_argument("-t", "--timeout", action="store", help="set the timeout of dns queries in seconds(default=30)")
    args = parser.parse_args()

    domain = args.domain.lower()
    domains = []
    # if we only check for tlds
    if args.tlds:
        domains = checkTld(loadTld(), domain)
    # if we only check for missing chars
    elif args.missing_chars:
        domains = checkMissingChar(domain)
    elif args.replace_chars:
        domains = checkReplaceChar(domain)
    # if we check both
    else:
        domains = checkTld(loadTld(), domain)
        domains += checkMissingChar(domain)
        domains += checkReplaceChar(domain)
    matches=dnsQuery(domains)
    if args.output !="":
        writeResults(args.output,matches)

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
def dnsQuery(domains):
    threads = []
    results = {}
    matches={}
    for address in domains:
        resolver_thread = Resolver(address, results)
        threads.append(resolver_thread)
        resolver_thread.start()

    for thread in threads:
        thread.join()

    for domain in results:
        #excluding the ICANN special IP
        if results[domain] != "127.0.53.53" :
            matches[domain]=results[domain]

    print "Queries : "+str(len(threads))
    print "Results : "+str(len(matches))
    return matches


# function loading the tlds
def loadTld():
    try:
        tldFile = open(TLD_FILENAME, "r")
    except IOError:
        print "error openning tld file"
    tlds = []
    for line in tldFile:
        tlds.append(line.rstrip('\n\r'))
    tldFile.close()
    return tlds

# function that write results to a file
def writeResults(file,results):
    try:
        file=open(file,"w")
        for domain in results.keys():
            file.write(domain+":"+results[domain]+"\n\r")
        file.close()

    except IOError:
        print "error writing file"



if __name__ == '__main__':
    main()