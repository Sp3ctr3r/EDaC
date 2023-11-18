import base64
import urllib.parse
import hashlib
import requests
import json
import os


def b64_encrypter():
    getText = input("\nEnter a text to encrypt : ")

    enc = base64.b64encode(getText.encode("utf-8"))

    print("\nInput Decrypted : ",enc, "\n")

def b64_decrypter():
    getText = input("\nEnter a text to decrypt : ")

    edited = getText[2:-1]

    decoded_bytes = base64.b64decode(edited.encode("utf-8"))
    
    dec = decoded_bytes.decode("utf-8")

    print("\nInput decrypted : ", dec, "\n")

def sha_encode():
    print("\n","****** Texts encoded with this encryption cannot be decoded again! ******","\n")
    text = input("Enter e text to decrypt : ")

    sha256 = hashlib.sha256()
    sha256.update(text.encode())

    decrypted_text = sha256.hexdigest()

    print("\n","Original Text: ", text)
    print("\n","Text Encrypted with SHA-256: ", decrypted_text, "\n")

def url_encode():
    text = str(input("Enter a url to encode : "))

    encoded = urllib.parse.quote(text)

    print("\n",encoded,"\n")

def url_decode():
    text = str(input("Enter a url to decode : "))
    
    encoded = urllib.parse.unquote(text)

    print("\n",encoded,"\n")

def ip_scan():
    getIp = input("Enter an ip address to scan :")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{getIp}"

    api = "apikey" # you need to add here your virustotal api key to use this

    headers = {
        "accept": "application/json",
        "x-apikey": api
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        attributes = data["data"]["attributes"]
        
        total_analyses = attributes["last_analysis_stats"]
        print(f"Total Number of Analyzes: {sum(total_analyses.values())}")
        
        results = attributes["last_analysis_results"]
        malicious_and_suspicious = []
        for engine_name, result in results.items():
            if result["category"] in ["malicious", "suspicious"]:
                malicious_and_suspicious.append((engine_name, result["category"]))
        
        malicious_and_suspicious.sort(key=lambda x: x[0])
        print("\n","Security Providers Deemed Harmful and Suspicious:","\n")
        for i, (engine_name, category) in enumerate(malicious_and_suspicious, start=1):
            print(f"{i}.{engine_name}: {category}")

        response_filename = f"virustotal_result_{getIp}.txt"
        with open(response_filename, "w") as file:
            file.write(response.text)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        record_path = os.path.join(script_dir, response_filename)
        print(f"\n","Log file created!","\n")

    else:
        print("Error: Request failed. Code:", response.status_code)


def cho():
    while True:
        print("1-> Encrypt text(Base64)\n2-> Decrypt text(Base64)\n3-> Url encode\n4-> Url decode\n5-> Sha256 encode\n6-> IP scan") 

        uCho = input("choose : ")

        if uCho == "1":
            b64_encrypter()

        elif uCho == "2":
            b64_decrypter()

        elif uCho == "3":
            url_encode()

        elif uCho == "4":
            url_decode()

        elif uCho == "5":
            sha_encode()

        elif uCho == "6":
            ip_scan()

        else:
            print("error!")
            continue

cho()
