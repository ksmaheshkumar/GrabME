#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

# Linux Bound!
# Author: https://twitter.com/GuerrillaWF

# Native imports
import re
import sys
import getopt

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
STATUS = paint.Y+"[STATUS]"+paint.N+":"

# TO-DO List:
# Add support for extracting things from MULTIPLE files.
# Possibly add database to aggregate extracted information
# Work on better case detection for diffent phone number formats
# Add other country SSN Number support, GrabSSN currently only supports USA SSNs
# Incorporate bitcoin pre-fixes into bitcoin grabbing function

# Add grab facebook api key/secret/access_token method.
# secret\s*[\=]+ <<< regex

# Bug Reports:
# Phone number false readinds.

# Current Draw backs:
# Can not grab any Bitcoin wallet addresses that are 31 - 32 characters in length.

# Grab Bitcoin Wallet Addresses
def GrabBitcoinWallet(fwbw):

    found = [] # List of found
    btcwsrch = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
    with open(fwbw, 'rb') as FileWithBitcoinAddress:
        for wallet in FileWithBitcoinAddress:
            wallet = wallet.replace('\n', '')
            if btcwsrch.findall(wallet):
                found.append(wallet)

    # remove duplicate link elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique link(s)
    return u.keys()

# Grab password hashes
def GrabHash(fohi):

    found = [] # List of found phone numbers
    md5srch = re.compile(r'[0-9a-f]{32}')
    sha1srch = re.compile(r'[0-9a-fA-F]{40}')
    sha256srch = re.compile(r'[0-9a-fA-F]{64}')
    sha384srch = re.compile(r'[0-9a-fA-F]{96}')
    sha512srch = re.compile(r'[0-9a-fA-F]{128}')


    with open(fohi, 'rb') as FileWithPhoneNumbers:
        for line in FileWithPhoneNumbers:
            hashtype = line.replace('\n', '')

            if md5srch.findall(hashtype):
                found.append(hashtype)

            if sha1srch.findall(hashtype):
                found.append(hashtype)

            if sha256srch.findall(hashtype):
                found.append(hashtype)

            if sha384srch.findall(hashtype):
                found.append(hashtype)

            if sha512srch.findall(hashtype):
                found.append(hashtype)

    # remove duplicate phone number elements
    u = {}
    for item in found:
        u[item] = 1

    #returns a list of unique phone number(s)
    return u.keys()

def GrabLink(fowl):

    found = [] # List of found links
    linksrch = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')

    with open(fowl, 'rb') as FileWithLinks:
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

    with open(fowipv6, 'rb') as FileWithCCN:
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

    with open(foccn, 'rb') as FileWithCCN:
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
    with open(fwssn, 'rb') as FileWithSSN:
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

    with open(fopn, 'rb') as FileWithPhoneNumbers:
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
    macsrch = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
    macsrch1 = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')
    #macsrch1 = re.compile(r'([a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2})')

    with open(fom, 'rb') as FileWithMACS:
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

    with open(foi, 'rb') as FileWithIPv4:
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

    with open(foe, 'rb') as FileWithEmail:
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
    GrabME - Extract Sensitive information from a file.

    Usage: ./grabme.py -f [FILE]

    OR

    ./grabme.py -f [FILE] -f [FILE] ... etc.

    What can it extract ?:

    Links
    hash values
    email addresses
    ipv4, ipv6 addresses
    bitcoin wallet addresses
    MAC addresses with : or - (deliminators)
    USA Based Telephone, Social Security and Major Credit Card numbers.
    """

def main(IFNOARGEXISTS):
    try:

        options, arguements = getopt.getopt(sys.argv[1:], 'f:')

        for opt, arg in options:

            if opt in '-f':

                try:
                    print ""

                    EmailExtract = GrabEmail(arg) # Collected emails
                    if len(EmailExtract) > 0: # legit file, containing at least 1 email address.
                        FoundEmails = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in EmailExtract:
                            EmailRegex = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
                            EmailContainer = EmailRegex.search(instance)
                            Emails = EmailContainer.group()
                            FoundEmails.append(Emails)
                        UOD = {}
                        for item in FoundEmails:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED Emails    ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO , output
                        print "\n", STATUS, "Extracted {} Email Address(es) from {}".format(str(count), arg)


                    IPv4Extract = GrabIPv4(arg) # Collected ipv4s
                    if len(IPv4Extract) > 0: # legit file, containing at least 1 ipv4 address.
                        FoundIPv4s = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in IPv4Extract:
                            IPv4Regex = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')
                            IPv4Container = IPv4Regex.search(instance)
                            IPv4s = IPv4Container.group()
                            FoundIPv4s.append(IPv4s)
                        UOD = {}
                        for item in FoundIPv4s:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED IPV4s     ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO , output
                        print "\n", STATUS, "Extracted {} IPv4(s) from {}".format(str(count), arg)

                    MACExtract = GrabMAC(arg)
                    if len(MACExtract) > 0: # legit file, containing at least 1 MAC, (: or - deliminated) address.
                        FoundMACS = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in MACExtract:
                            macsrch = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')
                            macsrch1 = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
                            cdm = macsrch.findall(instance)
                            hdm = macsrch1.findall(instance)
                            for mach in hdm: FoundMACS.append(mach)
                            for macc in cdm: FoundMACS.append(macc)
                        UOD = {}
                        for item in FoundMACS:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED MACs      ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO , output
                        print "\n", STATUS, "{} Extracted MAC address(es) from {}".format(str(count), arg)

                    PNExtract = GrabPhoneNumbers(arg)
                    if len(PNExtract) > 0 and len(PNExtract[0]) < 15: # Try not to grab any CCNs
                        FoundPhoneNumbers = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in PNExtract:
                            PNRegex = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$')
                            PNC = PNRegex.search(instance)
                            PN = PNC.group()
                            FoundPhoneNumbers.append(PN)
                        UOD = {}
                        for item in FoundPhoneNumbers:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo(" EXTRACTED Phone Numbers  ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            if output.isdigit() is False:
                                print INFO, output
                            else:
                                pass
                        print "\n", STATUS, "{} Extracted Phone Number(s) from {}".format(str(count), arg)

                    SSNExtract = GrabSSN(arg)
                    if len(SSNExtract) > 0: # legit file, containing at least 1 SSN, ( - deliminated) number.
                        FoundSSNs = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in SSNExtract:
                            SSN1Regex = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$')
                            SSN2Regex = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$')
                            SSN1LIST = SSN1Regex.findall(instance) # no deliminator
                            SSN2LIST = SSN2Regex.findall(instance) # - deliminator
                            for SSNV1 in SSN1LIST: FoundSSNs.append(SSNV1)
                            for SSNV2 in SSN2LIST: FoundSSNs.append(SSNV2)
                        UOD = {}
                        for item in FoundSSNs:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED SSNs      ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} SSN(s) from {}".format(str(count), arg)

                    CCNExtract = GrabCreditCard(arg)
                    if len(CCNExtract) > 0: # legit file, containing at least 1 CCN  numbers.
                        FoundCCNs = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in CCNExtract:
                            CCNRegex = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')
                            CCNLIST = CCNRegex.search(instance)
                            CCN = CCNLIST.group()
                            FoundCCNs.append(CCN)
                        UOD = {}
                        for item in FoundCCNs:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED CCNs      ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} CCN(s) from {}".format(str(count), arg)

                    IPv6Extract = GrabIPv6(arg)
                    if len(IPv6Extract) > 0: # legit file, containing at least 1 ipv6 number.
                        FoundIPV6s = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in IPv6Extract:
                            IPv6Regex = re.compile(r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$')
                            IPv6List = IPv6Regex.search(instance)
                            IPv6s = IPv6List.group()
                            FoundIPV6s.append(IPv6s)
                        UOD = {}
                        for item in FoundIPV6s:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED IPv6s     ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} IPv6(s) from {}".format(str(count), arg)

                    LinkExtract = GrabLink(arg)
                    if len(LinkExtract) > 0: # legit file, containing at least 1 link.
                        FoundLinks = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in LinkExtract:
                            LinkExtractRegex = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')
                            LinkList = LinkExtractRegex.search(instance)
                            Links = LinkList.group()
                            FoundLinks.append(Links)
                        UOD = {}
                        for item in FoundLinks:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("      EXTRACTED link(s)   ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} link(s) from {}".format(str(count), arg)

                    BTCWAExtract = GrabBitcoinWallet(arg)
                    if len(BTCWAExtract) > 0: # legit file, containing at least 1 link.
                        FoundWallets = [] # Re-filter, so you get exactly what you're looking for.

                        for instance in BTCWAExtract:
                            BTCWalletRegex = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
                            wallet = BTCWalletRegex.findall(instance)
                            for address in wallet: FoundWallets.append(address)
                        UOD = {}
                        for item in FoundWallets:
                            UOD[item] = 1
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("  EXTRACTED BTC Addresses ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} Bitcoin address('s) from {}".format(str(count), arg)

                    HashExtract = GrabHash(arg)
                    if len(HashExtract) > 0: # If you actually grab something then continue
                        FoundHashes = [] # Re-filter, so you get exactly what you're looking for.
                        for instance in HashExtract:
                            # Stand-alone regex's for finding hash values.
                            md5regex = re.compile(r'[a-fA-F0-9]{32}')
                            sha1regex = re.compile(r'[[a-fA-F0-9]{40}')
                            sha256regex = re.compile(r'[a-fA-F0-9]{64}')
                            sha384regex = re.compile(r'[a-fA-F0-9]{96}')
                            sha512regex = re.compile(r'[a-fA-F0-9]{128}')

                            # Find hash value of given regex's
                            md5list = md5regex.findall(instance)
                            sha1list = sha1regex.findall(instance)
                            sha256list = sha256regex.findall(instance)
                            sha384list = sha384regex.findall(instance)
                            sha512list = sha512regex.findall(instance)

                            # Add hash values to un-filtered list for filtering.
                            for md5 in md5list: FoundHashes.append(md5)
                            for sha1 in sha1list: FoundHashes.append(sha1)
                            for sha256 in sha256list: FoundHashes.append(sha256)
                            for sha384 in sha384list: FoundHashes.append(sha384)
                            for sha512 in sha512list: FoundHashes.append(sha512)

                        UOD = {} # Filter out any duplicates
                        for item in FoundHashes:
                            UOD[item] = 1 # No duplicates at all !
                        keys = UOD.keys()
                        PrintInfo("--------------------------")
                        PrintInfo("   Extracted Hash Values  ")
                        PrintInfo("--------------------------")
                        count = 0
                        for output in keys:
                            count += 1
                            print INFO, output
                        print "\n", STATUS, "Extracted {} Hash(es) found from {}".format(str(count), arg)

                    # The only real way to know if nothing returns at all.
                    if EmailExtract == [] and HashExtract == [] and BTCWAExtract == [] and LinkExtract == [] and IPv6Extract == [] and CCNExtract == [] and SSNExtract == [] and PNExtract == [] and MACExtract == [] and IPv4Extract == []:
                        PrintInfo(FAIL, "No supported extract detected from {}".format(arg))

                    print "" # Better looking output.

                except IndexError as e:
                    print e #| for debugging.
                    Help()
    except IndexError:
            Help()

def ExportFindingsToFile(filename='output.txt'):
    #Export findings to file.
    pass

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        Help()
