#!/usr/bin/python3
# Script Name: file_sha1_lookup.py
# Purpose: This script can be used to lookup SHA-1, SHA-256, and MD5 file hashes against Threat Exchange data in otx.alienvault.com
# Written By: Will Armijo
# Created on: 1/16/2025
# Please note, in order to use this script you will need to uncomment one of the following input code blocks first. Each one serves a different purpose. 

import requests
import json
import hashlib
import os

# Uncomment this block of code to enable user to enter file path. Rememeber 
# to uncomment the 'else' code at the very bottom too.
########################################################################
#file_path = input("Enter full file path(ex. /home/user/file): ")
#if os.path.exists(file_path):
#    print('The file exists')
#    file_hash = hashlib.sha1(open(file_path, 'rb').read()).hexdigest()
########################################################################

# Uncomment this block of code to enable user to enter file SHA-1 hash
#file_hash = input("Enter the files' SHA-1: ")

# Uncomment to test known bad SHA-1 hash. 
#file_hash = "33edac8a75cac4a0a1d084174b3dc912b9744386"

print("Looking up Info for this hash: ", file_hash)
analysis_url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"

print("Retreiving ", analysis_url)
response = requests.get(analysis_url)

if response.status_code == 200:
    hash_info = response.json()
    
    hash_details = hash_info
    pulses = hash_details['pulse_info']['pulses']

    for items in pulses:
        name = items['name']
        ids = items['attack_ids']
        descr = items['description']
        tags = items['tags']
        created = items['created']
        modified = items['modified']
        refs = items['references']
        adversary = items['adversary']
        affected_ind = items['industries']

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
        print("References:")
        for ref in refs:
            print(ref)
        print("")
        print("Affected Industries: ", affected_ind)
        print("")
        print("Associated Attacks:")
        for id in ids:
            print("\t", id['display_name'])
        print("")
else:
    print("Request failed with status", {response.status_code})

#else:
#    print('The file does not exist')
