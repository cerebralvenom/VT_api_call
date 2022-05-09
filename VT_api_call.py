import requests
import json
import sys
import re

n = len(sys.argv)

if n < 2:
    print("[!] Please enter an API-Key as your first arguement.")
    exit()

api_key = sys.argv[1]

print("\n[*] API-Key: ", sys.argv[1])

hash = input("[*] Enter the MD5 or SHA-256 hash you would like to check: ")
def hash_check(hash):
    md5_pat = re.compile(r"^[0-9a-fA-F]{32}$")
    sha256_pat = re.compile(r"^[0-9a-fA-F]{64}$")

    if re.fullmatch(md5_pat, hash) or re.fullmatch(sha256_pat, hash):
        print("\n[+] Correct Hash Format ")
    else:
        print("\n[!] Incorrect Hash Format: Quitting!")
        quit()


def api_call(api_key, hash):
    header = {'x-apikey': api_key}
    url = "https://www.virustotal.com/api/v3/files/" + hash 
    response = requests.get(url, headers=header)
    return response

def check_malicious(data):
    flag = "malicious"
    data = json.loads(data.text)
    data = data["data"]["attributes"]["last_analysis_results"]
    vendor_list = []
    results_list = []
    for a in data:
        vendor_list.append(a)
    for b in vendor_list:
        results_list.append(data[b]["category"])
    flag_count = 0
    for i in results_list:
        if flag in i:
            flag_count += 1
    return flag_count

def print_check_results(number):
    if number < 1:
        print("[+] File NOT malicious! Detected by 0 antivirus engines!")
    if number > 5:
        print("[!] File IS malicious! Detected by " + str(number) + " antivirus engines!")
    if number > 0 and number <= 5:
        print("[*] File MAYBE malicious! Detected by " + str(number) + " antivirus engines!")

def response_code(response):
    return_code = str(response)
    return_code = return_code.replace("<Response [","")
    return_code = return_code.replace("]>","")
    print("\n[*] API Response Code: " + return_code)
    if return_code != "200":
        if return_code == "404":
            print("\n[!] API Return code 404: No Results for File Hash")
            print("[*] If you believe this is an error, manually enter the file hash at https://www.virustotal.com/gui/home/search.")
        else:
            print("\n[!] Return code not 200: API failure.")
            print("[*] Check your API key and file hash.")
        exit()
        
        
hash_check(hash)
final = api_call(api_key, hash)
response_code(final)
print_check_results(check_malicious(final))

