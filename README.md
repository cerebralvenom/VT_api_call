# VT_api_call
Make an api call with a file hash to Virus Total, get the number of malicious flags back. 

First you'll need to get your API Key from virus total. You can sign up for free and get one.

Then clone this repository down. 

**Requires Python3.**


**Syntax is: python3 vt_api_call.py [YOUR API KEY]**



The program will ask you for a MD5 or SHA-256 hash, and it will validate it. 

Then you will recieve results. 


**NOTE:** 404 Errors to the VT API mean that no results were returned so the file has not been scanned yet. It does not mean anything about whether or not the files is malicious.  
