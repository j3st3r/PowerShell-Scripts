#!/usr/bin/python3
# Script Name: ip_otx.py
# Description: Use to retreive possible IoC (Indicators of Compromise) info for IP Addresses via otx.alienvault.com
# Written By Will Armijo
# Created On: 01/11/2025

import requests
import json

print("This script is used to lookup reputational data for an IP Address")

ip_addr = input("Please Enter an IP Address: ")

url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_addr}/general"
print("Retreiving ", url)
response = requests.get(url)

if response.status_code == 200:
    print("Successfully Accessed:", {url})
    ip_info = response.json()

    if ip_info["false_positive"]:
        print("False Positive - Not  Malicious")
    else:
        pulses = ip_info['pulse_info']['pulses']


for items in pulses:
   name = items['name']
   descr = items['description']
   tags = items['tags']
   created = items['created']
   modified = items['modified']

# Reporting Section
print("==================")
print("IoC Information: ")
print("==================")
print("")
print("IoC Name: ", name)
print("IoC Description: ", descr)
print("IoC Created on: ", created)
print("Last Updated", modified)
print("Number of related IPs:", ioc_counts['IPv4'])
print("Number of related MD5  fingerprints:", ioc_counts['FileHash-MD5'])
print("Number of related SHA-1 fingerprints:", ioc_counts['FileHash-SHA1'])
print("Number of related URLs:", ioc_counts['URL'])
print("Related Tags: ", tags)
print("==================")
print("IoC Details: ")
print("==================")
print("")
for items in pulses:
    description = items['description']
    print(description)
    print("")

print("===============")
print("Identified by: ")
print("===============")
print("")
for items in pulses:
    source_name = items['name']
    print(source_name)
    
else:
    print("Request failed with status", {response.status_code}) # Error Code here
