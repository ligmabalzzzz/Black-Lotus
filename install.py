#!/usr/bin/env python3
#Black Lotus v2-dev-
#Copyright of The Jester 
#----------------------------------------------------------------------------------------------------------------------
import os
print("\033[31mBlack Lotus is doing some updates for you")
print("This may take a while.. Grab a coffee\033[37m ")
os.system("sudo apt-get update -y && sudo apt-get upgrade -y")
print("\033[37mInstalling all requirements...")
os.system("sudo apt-get install git -y")
os.system("sudo apt-get install ufw -y")
os.system("sudo apt-get install wget -y")
os.system("sudo apt-get install python3")
os.system("sudo apt-get install nmap -y")
os.system("sudo apt-get install metasploit-framework -y")
os.system("sudo apt-get install sqlmap -y")
os.system("sudo apt-get install wireshark -y")
os.system("sudo apt-get install shodan -y")
os.system("sudo apt-get install etherape -y")
os.system("git clone https://github.com/Und3rf10w/kali-anonsurf.git")
os.system("cd kali-anonsurf")
os.system("sudo chmod +x installer.sh")
os.system("sudo ./installer.sh")
os.system("cd ..")
os.system("sudo apt-get install wifite -y")
os.system("sudo apt-get install macchanger -y")
os.system("sudo apt-get install exploitdb -y")
os.system("sudo apt-get install metagoofil -y")
os.system("sudo apt-get install python3 -y")
os.system("sudo apt-get install python3-pip -y")
os.system("sudo apt-get install nbtscan -y")
os.system("sudo apt-get install nmblookup -y")
os.system("sudo apt-get install smbclient -y")

print("\n\033[37m[\033[33m!\033[37m] \033[31m Testing and installing libraries..")
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
os.system("pip install opencv-python")

print("\n\033[31mCreating Black Lotus Launcher...\033[37m")
lotus_launcher_code=(r"""[Desktop Entry]
Version=1.0
Name=Black Lotus
Comment=Black Hat Hacker Toolkit """)
tool_dir = input("Enter blacklotus.py directory \n For example: '/home/user/Black-Lotus/blacklotus.py' > ")
launcher_exec=("Exec=sudo -k -u root " + tool_dir)
icon_dir = input("Enter your desired icon \n For example: '/home/user/Black-Lotus/blacklotus.jpg/png' > ")
launcher_icon = ("Icon=" + icon_dir)
lotus_launcher_code2=(r"""Terminal=true
Type=Application
Categories=Utility;Application;
Path=
StartupNotify=false
""")
code_mal = str(lotus_launcher_code + "\n" + launcher_exec + "\n" + launcher_icon + "\n" + lotus_launcher_code2)
launcher_rev=open("blacklotus2.desktop","w+")
launcher_rev.write(code_mal)
launcher_rev.close()
os.system("sudo chmod +x blacklotus.desktop")
dir_save = input(" Enter directory to save the executable >")
command_launcher = str("sudo mv blacklotus.desktop " + dir_save)
os.system(command_launcher)
print("\n\033[31mWe think that thats all, download finished! \n For help or assist check my github: https://github.com/th3-jes7er")
