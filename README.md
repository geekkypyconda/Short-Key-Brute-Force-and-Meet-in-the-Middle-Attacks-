# Short-Key-Brute-Force-and-Meet-in-the-Middle-Attacks-

## Short Key Brute Force

## How to Run the Program
-------------------------

### Steps

1. Run the file "cs23mtech11005_A.py" to get the key and the special message.
2. This program uses a brute force attack by trying all possible keys to find the exact key.
3. Once the key is found, it is used to crack the special message.

### Other Mentions
-----------------

* The file "aesLongKeyGen24.py" is used to expand the key.
* The program reads from the files "aesCiphertexts.txt" and "aesPlaintexts.txt".
* The special message is written to the file "aesSecretMessage.txt".

## Meet in the Middle Attack

## How to Run the Program
-------------------------

### Steps

1. Run the file "cs23mtech11005_B.py" to get the key pair and the special message.
2. This program uses a Meet in the Middle attack by encrypting from one side and decrypting from the other side, and then comparing to find the key pair.
3. Once the key pair is found, it is used to find the secret message.

### Other Mentions
-----------------

* The file "2aesLongKeyGen16.py" is used to expand the key.
* The program reads from the files "2aesCiphertexts.txt" and "2aesPlaintexts.txt".
* The special message is written to the file "2aesSecretMessage.txt".
