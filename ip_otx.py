#!/usr/bin/python3
# Script Name: OTX
# Description: Used to retreive IOC info for IP Addresses from otx.alienvault.com
# Written By Will Armijo
# Version 1
import requests
import json

print("")
print("This script is used to lookup reputational data for an IP Address")
print("")

ip_addr = input("Please Enter an IP Address: ")

url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_addr}/general"
print("Retreiving ", url)
response = requests.get(url)

if response.status_code == 200:
    print("Successfully Accessed:", {url})
    ip_info = response.json()

    if ip_info["false_positive"]:
        print("NOT Malicious")
    else:
        print(json.dumps(ip_info["pulse_info"], indent=0))
else:
    print("Request failed with status", {response.status_code})
