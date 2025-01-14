#!/usr/bin/python3
# Script Name: url_otx.py
# Description: Use to retreive possible IoC (Indcator of Compromise) info for URLs from otx.alienvault.com API.
# Written by Will Armijo

import requests
import json

ioc_url = input("Please Enter the Domain name(example: https://www.google.com): ")

url = f"https://otx.alienvault.com/api/v1/indicators/url/{ioc_url}/general"
print("Retreiving ", url)
response = requests.get(url)

if response.status_code == 200:
    print("Successfully Accessed:", {url})
    ip_info = response.json()

    if ip_info["false_positive"]:
        print("False Positive - Not  Malicious")
    else:
        pulses = ip_info['pulse_info']['pulses']

    #print(pulses)
    for items in pulses:
        name = items['name']
        descr = items['description']
        trgtd_countries = items['targeted_countries']
        tags = items['tags']
        created = items['created']
        modified = items['modified']
        references = items['references']
    
    #print(pulses)
    print("")
    print("==================")
    print("IoC Information: ")
    print("==================")
    print("")
    print("IoC Name: ", name)
    print("IoC Description: ", descr)
    print("")
    print("IoC Created on: ", created)
    print("Last Updated", modified)
    print("")
    print("Targeted Countries")
    for tgt_cnty in trgtd_countries:
        print(tgt_cnty)
    print("")
    print("References")
    for refs in references:
        print(refs)

else:
    print("Request failed with status", {response.status_code})
