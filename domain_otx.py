#!/usr/bin/python3
# Script Name: domain_otx.py
# Description: Use to retreive possible IoC (Indcator of Compromise) info for Domain Names from otx.alienvault.com API.
# Written by Will Armijo

import requests
import json

print("This script is used to lookup reputational data for a Domain")

domain = input("Please Enter the Domain name(example: google.com): ")

url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
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

print("==================")
print("IoC Information: ")
print("==================")
print("")
print("IoC Name: ", name)
print("IoC Description: ", descr)
print("IoC Created on: ", created)
print("Last Updated", modified)
print(tags)
print("")

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
    print("Request failed with status", {response.status_code})
