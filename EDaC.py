import base64
import urllib.parse
import hashlib
import requests
import json
import os


def b64_encrypter():
    getText = input("\nŞifrelenecek metni girin : ")

    enc = base64.b64encode(getText.encode("utf-8"))

    print("\nGirdi şifrelendi : ",enc, "\n")

def b64_decrypter():
    getText = input("\nÇözülecek metni girin : ")

    edited = getText[2:-1]

    decoded_bytes = base64.b64decode(edited.encode("utf-8"))
    
    dec = decoded_bytes.decode("utf-8")

    print("\nGirdi çözüldü : ", dec, "\n")

def sha_encode():
    print("\n","****** Bu şifreleme ile encode edilen metinler tekrar decode edilemez! ******","\n")
    text = input("Encode edilecek metin girin : ")

    sha256 = hashlib.sha256()
    sha256.update(text.encode())

    sifrelenmis_metin = sha256.hexdigest()

    print("\n","Orijinal Metin: ", text)
    print("\n","SHA-256 ile Şifrelenmiş Metin: ", sifrelenmis_metin, "\n")

def url_encode():
    text = str(input("Encode edilecek url : "))

    encoded = urllib.parse.quote(text)

    print("\n",encoded,"\n")

def url_decode():
    text = str(input("Decode edilecek url : "))
    
    encoded = urllib.parse.unquote(text)

    print("\n",encoded,"\n")

def ip_scan():
    getIp = input("Taranacak ip adresi :")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{getIp}"

    api = "apikey"

    headers = {
        "accept": "application/json",
        "x-apikey": api
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        attributes = data["data"]["attributes"]
        
        total_analyses = attributes["last_analysis_stats"]
        print(f"Toplam Analiz Sayısı: {sum(total_analyses.values())}")
        
        results = attributes["last_analysis_results"]
        malicious_and_suspicious = []
        for engine_name, result in results.items():
            if result["category"] in ["malicious", "suspicious"]:
                malicious_and_suspicious.append((engine_name, result["category"]))
        
        malicious_and_suspicious.sort(key=lambda x: x[0])
        print("\n","Zararlı ve Şüpheli Bulunan Güvenlik Sağlayıcıları:","\n")
        for i, (engine_name, category) in enumerate(malicious_and_suspicious, start=1):
            print(f"{i}.{engine_name}: {category}")

        response_filename = f"virustotal_result_{getIp}.txt"
        with open(response_filename, "w") as file:
            file.write(response.text)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        record_path = os.path.join(script_dir, response_filename)
        print(f"\n","Kayıt dosyası oluşturuldu!","\n")

    else:
        print("Hata: İstek başarısız. Kod:", response.status_code)


def cho():
    while True:
        print("1-> Metin şifrele(Base64)\n2-> Metni çöz(Base64)\n3-> Url encode\n4-> Url decode\n5-> Sha256 encode\n6-> IP scan") 

        uCho = input("seçim : ")

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
            print("hata!")
            continue

cho()
