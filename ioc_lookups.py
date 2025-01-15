#!/usr/bin/python3
# Script Name: ioc_lookups.py
import json
import os
import pandas as pd
from pandas import json_normalize
import requests

print("")
print("=============================================================")
def options():
    print("")
    print("Indicator of Compromise Lookups")
    print("1. Lookup IoC data for an IP Address from OTX")
    print("2. Lookup IoC data for an IP Rep from Virus Total")
    print("3. Lookup IoC data for a Domain")
    print("4. Lookup IoC data for a URL")
    print("5. Exit")
    print("")
print("=============================================================")
while True:
    options()
    choice = int(input("Enter your choice: "))
    
    if choice == 1:
        ip_addr = input("Please Enter an IP Address: ")
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_addr}/general"
        print("")
        response = requests.get(url)
        
        if response.status_code == 200:
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
            refs = items['references']
            adversary = items['adversary']

        # Reporting Section
        print("==================")
        print(" IoC Information: ")
        print("==================")
        print("")
        print("IoC Name: ", name)
        print("Adversary: ", adversary)
        print("IoC Description: ", descr)
        print("IoC Created on: ", created)
        print("Last Updated", modified)
        print("Related Tags", tags)
        print("References:", refs)
        print("")

        print("==================")
        print(" IoC Details: ")
        print("==================")
        print("")
        for items in pulses:
            description = items['description']
            print(description)
            print("")

        print("===============")
        print(" Identified by: ")
        print("===============")
        print("")
        for items in pulses:
            source_name = items['name']
            print(source_name)
        else:
            print("Request failed with status", {response.status_code}) # Error Code here
            
    elif choice == 2:
        ip_addr = input("Please Enter an IP Address: ")
        api_key = "01ec9abc02ecd5e18bd1e554ceef89e98937ca595c7df433a4889c840cf530d3"
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}"

        # Set up the headers
        header = {
            'X-Apikey': f'{api_key}',
            'Content-Type': 'application/json'
            }

        response = requests.get(url, headers=header)

        if response.status_code == 200:
            vt_data = response.text
    
            df = pd.read_json(vt_data)

            ioc_total = df['data']
            ioc_ip = df['data']['id']
            ioc_atrb = df['data']['attributes']
            network = ioc_atrb['network']
            ioc_rep = ioc_atrb['reputation']
            ioc_tags = ioc_atrb['tags']
            ioc_results = df['data']['attributes']['last_analysis_stats']

            print("")
            print(" IoC Results for", ioc_ip)
            print("=====================================")
            print("")
            print(" Target IP: ", ioc_ip)
            print(" Target Network", network)
            print("")
            print("=====================================")
            print(" Antimalware Scan Engines IoC Results")
            print(" Found to be Malicious ", ioc_results['malicious'], "times")
            print(" Found to be Suspicious ", ioc_results['suspicious'], "times")
            print(" Found to be Undetected ", ioc_results['undetected'], "times")
            print(" Found to be Harmless ", ioc_results['harmless'], "times")

        else:
            print("Request failed with status", {response.status_code}, {response.text})
    
    elif choice == 3:
        domain = input("Please Enter the Domain name(example: google.com): ")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        response = requests.get(url)

        if response.status_code == 200:
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
        else:
            print("Request failed with status", {response.status_code})

    elif choice == 4:
        ioc_url = input("Please Enter the Domain name(example: https://www.google.com): ")
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{ioc_url}/general"
        response = requests.get(url)

        if response.status_code == 200:
            ip_info = response.json()

            if ip_info["false_positive"]:
                print("False Positive - Not  Malicious")
            else:
                pulses = ip_info['pulse_info']['pulses']

            #print(pulse informationo)
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
    elif choice == 5:
        break
    else:
        print("")
        print("Not an Option, try again!")
        print("")
    print("")
    print("*******************************************************************")
