<h1>fpublicity</h1>
<p align="center"><img src="fpublicity.gif" alt="fpublicity Logo"></p>
<p>* Private Live-chat based on TCP/IP connections</p>
<p>* Written in Python3 with <a href="https://github.com/x64bitworm">@x64bitworm</a></p>

# Installation

**Linux:**
```
sudo apt-get install libasound2-dev build-essential libssl-dev libffi-dev python3-dev
python3 -m pip install -r requirements.txt
```
  
**Windows:**  
If you are having trouble with Visual Cpp Build-Tools you can easily install it [here](https://download.microsoft.com/download/5/f/7/5f7acaeb-8363-451f-9425-68a90f98b238/visualcppbuildtools_full.exe)
```
python -m pip install -r requirements.txt
```
  
# About room keys
Remember! Never share your room keys over Internet without proper asymmetric encryption if you want to stay private. For sharing keys securely we've made kshare.py
  
# About kshare.py
Using kshare.py you can securely share your secret room keys over Internet.  
### How it works
It uses advanced asymmetric RSA-4096 cipher algorithm to encrypt AES-256 key that comes inside encrypted key. When ciphered room key is decrypted, AES-256 key is decrypted using your RSA-4096 Private key and then decrypts the whole room key.  
### How to share
Example: Alice wants to share her room key with Bob  
1. Bob generates Private and Public key using RSA-4096  
```
python3 kshare.py rsa-4096 -prk private_key.pem -puk public_key.pem
```
As an output he gets 2 files (public_key.pem and private_key.pem)  
  
2. Bob sends his public_key.pem (Public key) to Alice. (Remember! Never send your private_key.pem (Private key) to anyone)  
  
3. Alice now can encrypt her room key file with Bob's Public key  
```
python3 kshare.py encrypt -puk public_key.pem -f room_key.bin -o crypted_room_key.crypt
```
As an output she gets encrypted room key file (crypted_room_key.crypt)  
  
4. Alice sends crypted_room_key.crypt file to Bob  
  
5. Now Bob can decrypt Alice's crypted room key file using his own Private key (private_key.pem) he has already generated.  
```
python3 kshare.py decrypt -prk private_key.pem -f crypted_room_key.crypt -o room_key.bin
```
Bob gets the final output room_key.bin (Room key) file that is the same as Alice's room_key.bin
