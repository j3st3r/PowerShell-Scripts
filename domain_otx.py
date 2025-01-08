#!/usr/bin/python3
# Script Name: domain_otx.py
# Description: Use to retreive possible IoC (Indcator of Compromise) info for Domain Names from otx.alienvault.com API.
# Written by Will Armijo

import requests
import json

domain = input("Please Enter the Domain name(example: google.com): ")

url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
print("Retreiving ", url)
response = requests.get(url)

if response.status_code == 200:
    print("Successfully Accessed:", {url})
    domain_info = response.json()

    if domain_info["false_positive"]:
        print("False Positive")
    else:
        print(json.dumps(domain_info["pulse_info"], indent=0))
else:
    print("Request failed with status", {response.status_code})
