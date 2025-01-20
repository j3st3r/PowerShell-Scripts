Script Name: IOC_Lookup_IP.ps1

Purpose: Use this script to obtain any IoC (Indicator of Compromise) details for a suspicious looking IP Address via AlienVaults’ OTX Threat Exchange.

Usage: ./IOC_Lookup_IP.ps1

Requires PowerShell

==========================================================================================================

Script Name: domain_otx.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking domain name via AlienVaults’ OTX Threat Exchange.

Usage: ./domain_otx.py

==========================================================================================================

Script Name: file_sha1_lookup.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking file hashes via AlienVaults’ OTX Threat Exchange.

Usage: ./domain_otx.py

Required Modules:
  + requests
  + json

==========================================================================================================

Script Name: ip_otx.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking IP Address via AlienVaults’ OTX Threat Exchange.

Usage: ./ip_otx.py

Required Modules:
  + requests
  + json
    
==========================================================================================================

Script Name: url_otx.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking URL via AlienVaults’ OTX Threat Exchange.

Usage: ./url_otx.py

Required Modules:
  + requests
  + json


==========================================================================================================

Script Name: virus_total_ip_lookup.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking IP Address via Virus Total.

Usage: ./virus_total_ip_lookup.py

Requried Modules:
  + request
  + json
  + pandas

==========================================================================================================

Script Name: virus_total_hash_lookup.py

Purpose: Use this script to lookup the IoC (Indicator of Compromise) details for a suspicious looking file via Virus Total. This sscript uses the hash (sha-1, sha-256, and md5) to look up possible IoC info.

Usage: ./virus_total_hash_lookup.py

Requried Modules:
  + request
  + json
  + pandas

==========================================================================================================
