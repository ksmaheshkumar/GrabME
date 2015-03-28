#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

# Linux Bound!
# Author: https://twitter.com/GuerrillaWF

import re
import sys

class paint():

    # Console paint
    N = '\033[0m' #  (normal)
    W = '\033[1;37m' # white
    R = '\033[31m' # red
    G = '\033[32m' # green
    O = '\033[33m' # orange
    B = '\033[34m' # blue
    P = '\033[35m' # purple
    C = '\033[36m' # cyan
    T = '\033[93m' # tan
    Y = '\033[1;33m' # yellow
    GR = '\033[37m' # gray
    BR = '\033[2;33m' # brown

INFO = paint.W+"[FOUND]"+paint.N+":"
FAIL = paint.R+"[FAILED]"+paint.N+":"

# TO-DO List:
# Shorten ipv6 regex
# Extract actual string from text
# Add support for extracting things from MULTIPLE files.
# Possibly add database to aggregate extracted information
# Work on better case detection for diffent phone number formats
# Add other country SSN Number support, GrabSSN currently only supports USA SSNs

def GrabLink(fowl):

    found = [] # List of found links
    linksrch = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')

    with open(fowl, 'r') as FileWithLinks:
        for line in FileWithLinks:
            links = line.replace('\n', '')
            if linksrch.findall(links):
                found.append(links)

    # remove duplicate link elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique link(s)
    return u.keys()

def GrabIPv6(fowipv6):

    found = [] # List of found ipv6 numbers

    ipv6srch = re.compile(r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$")

    with open(fowipv6, 'r') as FileWithCCN:
        for line in FileWithCCN:
            ipv6addr = line.replace('\n', '')
            if ipv6srch.findall(ipv6addr):
                found.append(ipv6addr)

    # remove duplicate ipv6 elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique ssn numbers
    return u.keys()

def GrabCreditCard(foccn):
    # Supports detection for these Credit Card Types:

            # Visa
            # MasterCard
            # Discover
            # AMEX
            # Diners Club
            # JCB

    found = [] # List of found Credit card numbers

    ccsrch = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')

    with open(foccn, 'r') as FileWithCCN:
        for line in FileWithCCN:
            cnumbers = line.replace('\n', '')
            if ccsrch.findall(cnumbers):
                found.append(cnumbers)

    # remove duplicate Cred card number elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique CCN numbers
    return u.keys()

def GrabSSN(fwssn):

    found = [] # List of found SSN numbers
    ssnsrch = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$') # USA based.
    ssnsrch2 = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$') # USA based.
    with open(fwssn, 'r') as FileWithSSN:
        for line in FileWithSSN:
            numbers = line.replace('\n', '')

            if ssnsrch.findall(numbers): # adds SSN with (-) to list
                found.append(numbers)

            if ssnsrch2.findall(numbers): # adds SSN without (-) to list
                found.append(numbers)

    # remove duplicate ssn elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique ssn numbers
    return u.keys()

def GrabPhoneNumbers(fopn):

    found = [] # List of found phone numbers
    phonesrch = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$') # North american based.

    with open(fopn, 'r') as FileWithPhoneNumbers:
        for line in FileWithPhoneNumbers:
            numbers = line.replace('\n', '')
            if phonesrch.findall(numbers):
                found.append(numbers)

    # remove duplicate phone number elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique phone number(s)
    return u.keys()

def GrabMAC(fom):

    found = [] # List of found MAC (:, -, . deliminated) addresses
    macsrch = re.compile(r'^([0-9A-F]{1,2})\:([0-9A-F]{1,2})\:([0-9A-F]{1,2})\:([0-9A-F]{1,2})\:([0-9A-F]{1,2})\:([0-9A-F]{1,2})$')
    macsrch1 = re.compile(r'^([0-9A-F]{1,2})\-([0-9A-F]{1,2})\-([0-9A-F]{1,2})\-([0-9A-F]{1,2})\-([0-9A-F]{1,2})\-([0-9A-F]{1,2})$')


    with open(fom, 'r') as FileWithMACS:
        for line in FileWithMACS:
            macs = line.replace('\n', '')

            if macsrch.findall(macs):
                found.append(macs)

            if macsrch1.findall(macs):
                found.append(macs)

    # remove duplicate MAC elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique mac addresses
    return u.keys()


def GrabIPv4(foi):

    found = [] # List of found ipv4 addresses
    ipv4srch = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')

    with open(foi, 'r') as FileWithIPv4:
        for line in FileWithIPv4:
            ipv4 = line.replace('\n', '')
            if ipv4srch.findall(ipv4):
                found.append(ipv4)

    # remove duplicate ipv4 elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique ipv4 addresses
    return u.keys()

def GrabEmail(foe):
    # if passed a list of text files, will return a list of
    # email addresses found in the files, matched according to
    # basic address conventions. Note: supports most possible
    # names, but not all valid ones.

    found = [] # List of found emails
    mailsrch = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

    with open(foe, 'r') as FileWithEmail:
        for line in FileWithEmail:
            email = line.replace('\n', '')
            if mailsrch.findall(email):
                found.append(email)
        #return found | for debugging, when the code goes out of style.

    # remove duplicate email elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique email addresses
    return u.keys()

def PrintInfo(sign='', pdata=''):
    print sign, pdata

def Help():
    print """
    """+paint.W+"""[GWF Certified]"""+paint.N+""" - """+paint.B+"""https://twitter.com/GuerrillaWF"""+paint.N+"""

    GrabME - Extract Sensitive information from a file.

    Usage: """+paint.Y+"""./grabme.py"""+paint.N+""" [FILE]

    What can it extract ?:

    Links
    email addresses
    ipv4, ipv6 addresses
    MAC addresses with : or - (deliminators)
    USA Based Telephone, Social Security and Major Credit Card numbers.
    """

def main():

    try:
        main1 = GrabEmail(sys.argv[1]) # Collected emails
        if len(main1) > 0: # legit file, containing at least 1 email address.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED Emails    ")
            PrintInfo("--------------------------")
            for email in main1:
                print INFO, email

        main2 = GrabIPv4(sys.argv[1]) # Collected emails
        if len(main2) > 0: # legit file, containing at least 1 ipv4 address.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED IPV4s     ")
            PrintInfo("--------------------------")
            for ipv4 in main2:
                print INFO, ipv4

        main3 = GrabMAC(sys.argv[1])
        if len(main3) > 0: # legit file, containing at least 1 MAC, (: or - deliminated) address.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED MACs      ")
            PrintInfo("--------------------------")
            for mac in main3:
                print INFO, mac

        main4 = GrabPhoneNumbers(sys.argv[1])
        if len(main4) > 0 and len(main4[0]) < 15: # Try not to grab any CCNs
            PrintInfo("--------------------------")
            PrintInfo(" EXTRACTED Phone Numbers  ")
            PrintInfo("--------------------------")
            for pn in main4:
                print INFO, pn

        main5 = GrabSSN(sys.argv[1])
        if len(main5) > 0: # legit file, containing at least 1 SSN, ( - deliminated) number.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED SSNs      ")
            PrintInfo("--------------------------")
            for SSN in main5:
                print INFO, SSN

        main6 = GrabCreditCard(sys.argv[1])
        if len(main6) > 0: # legit file, containing at least 1 CCN  numbers.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED CCNs      ")
            PrintInfo("--------------------------")
            for CCN in main6:
                print INFO, CCN

        main7 = GrabIPv6(sys.argv[1])
        if len(main7) > 0: # legit file, containing at least 1 ipv6 number.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED IPv6s     ")
            PrintInfo("--------------------------")
            for CCN in main7:
                print INFO, CCN

        main8 = GrabLink(sys.argv[1])
        if len(main8) > 0: # legit file, containing at least 1 link.
            PrintInfo("--------------------------")
            PrintInfo("      EXTRACTED link(s)   ")
            PrintInfo("--------------------------")
            for link in main8:
                print INFO, link

        if main1 == [] and main2 == [] and main3 == [] and main4 == [] and main5 == [] and main6 == [] and main7 == [] and main8 == []:
            PrintInfo(FAIL, "No supported extract detected!")

    except Exception as e:
        #print e | for debugging.
        Help()

if __name__ == "__main__":
    main()
