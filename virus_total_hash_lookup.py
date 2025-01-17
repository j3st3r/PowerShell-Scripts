#!/usr/bin/python3
# Script Name: virus_total_hash_lookup.py
# Purpose: Use to lookup Virus Total Stats for any file hash.
# Written By: Will Armijo
# Created on: 01/11/2025

'''
Please note that this script is not compliant with security as the API key is statically assigned. 
This can be updated to retrieve the API key from a protected file, user input, or user environment variable. 
'''

import requests
import json
import pandas as pd
from pandas import json_normalize

# Use one of the following hashes to test script with. These are known bad files hashes.
#hash = "33edac8a75cac4a0a1d084174b3dc912b9744386"
#hash = "7e328600053285468f4dd7c302cdc00d3a75ae89"
#hash = "39f9157e24fa47c400d4047c1f6d9b4dbfd067288cfe5f5c0cc2e8449548a6e8"

# Comment the 'hash' variable out if you choose one of the hashes above.
hash = input("Please enter a SHA-1 file hash: ")
api_key = "<Replace this with your own API key from Virus Total>"
url = f"https://www.virustotal.com/api/v3/files/{hash}"

# Set up the headers
header = {
    'X-Apikey': f'{api_key}',
    'Content-Type': 'application/json'
}

response = requests.get(url, headers=header)
print("Retreiving ", {url})
print("")


if response.status_code == 200:
    vt_data = response.text
    
    df = pd.read_json(vt_data)

    ioc_total = df['data']
    
    print("")
    #print(ioc_total['attributes'])
    print("")
    print("============================")
    print("")
    #print(ioc_total['attributes']['popular_threat_classification'])
    print("Detected as: ", ioc_total['attributes']['popular_threat_classification']['suggested_threat_label'])
    print("============================")
    print("")
    
    ioc_analysis = ioc_total['attributes']['last_analysis_stats']
    #print(ioc_analysis)
    print("Number of Antivirus to find file hash...") 
    print("\tMalicious:", ioc_analysis['malicious'])
    print("\tSuspicious:", ioc_analysis['suspicious'])
    print("\tUndetected:", ioc_analysis['undetected'])
    print("\tHarmlessby :", ioc_analysis['harmless'])
    print("\tTimedout by :", ioc_analysis['timeout'])
    print("\tFailure by :", ioc_analysis['failure'])
    print("\tType-Unsupported:", ioc_analysis['type-unsupported'])
    print("")

elif response.status_code == 400:
    print("ERROR: Invalid file hash")
elif response.status_code == 404:
    print("ERROR: No IoC records for this file hash")
else:
    print("ERROR: Request failed with status", {response.status_code}, {response.text})
