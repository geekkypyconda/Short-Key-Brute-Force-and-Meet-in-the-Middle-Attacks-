# Importing libraries
import os,binascii       
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen24 import *
import time
from ast import Bytes

#variable for storing all cipher text in hexadecimal
hexaCipherText = []
#variable for storing all plain texts
plainText = []
# Variable for storing all keys in hexadecimal
allHexaKeys = []
# Variables for storing short and long key
globalAES_ShortKey = ""
globalAES_LongKey = ""

# function for printing with next line
def println(object):
    print(object)
    print()


# Function for printing list
def printList(l):
    loop = 0
    for content in l:
        loop += 1
        print(f"{loop}. {content}")
    print()

# Function to read file
def readFile(path):
    l = []
    f = open(path,"r")
    for line in f:
        l.append(line.rstrip())
    
    return l

# Function to generate all the keys in bytes
def generateAllKeysBytes(sizeInBytes):
    allKeys = []
    
    start = time.time()
    
    #Trying for all possible keys
    for oneKey in range(2**20):
        shiftedKey = oneKey << 4
        byteKey = shiftedKey.to_bytes(sizeInBytes, byteorder = 'big')
        allKeys.append(byteKey)

    end = time.time()
    totalTime = end - start
    
    # returning list of all keys and time taken
    return allKeys, totalTime


# Function to encrypt using AES
def AES_GetCipherText(cipherObject,message):
    messageBytes = message.encode('UTF-8')
    encryptorObject = cipherObject.encryptor()
    cipherText = encryptorObject.update(messageBytes) + encryptorObject.finalize()
    
    return cipherText

# Function for verifying key
def breakAES(key):
    global globalAES_LongKey, globalAES_ShortKey
    #Generate random 3-byte key and expand it
    shortKeyBytes = key 
    shortKey=bytearray(shortKeyBytes)
    #Expand key to 128 bits
    key=expandKey(shortKey)
    
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipherObject = Cipher(algorithms.AES(key), modes.CBC(IV))    
    #Read and encrypt messages
    
    matchFound = 0
    
    for index in range(0,4):
        message = plainText[index]
        originalCipher = hexaCipherText[index]
        aesCipher = AES_GetCipherText(cipherObject, message)
        
        # Running for all the messages and if true then increase matchFound by 1
        if aesCipher.hex() == originalCipher:
            print("Match Found!")
            print("Expanded Key=",key.hex())
            print("Cracked Message : " + message)
            println("Original Cipher : " + originalCipher)
            globalAES_LongKey = key.hex()
            matchFound += 1
    
    # If all the messages are verified then return 1 else 0
    if matchFound == 4:
        return 1
    
    return 0

# Function for looping through one key
def loopForKeys(i,j):
    global allHexaKeys, globalAES_ShortKey
    
    # Checking for all the keys in range i to j
    for index in range(i,j + 1):
        oneKey = allHexaKeys[index]
        # print(f"Trying to break AES for Key : " + str(oneKey.hex()))
        
        # Getting the result in res and if it is 1 then match found 
        res = breakAES(oneKey)
        if res == 1:
            print("Match Found!")
            globalAES_ShortKey = oneKey.hex()
            return 1
    
    println("Match Not Found")
    return 0

# Function to break the cipher text
def breakCipher():
    global plainText, hexaCipherText, allHexaKeys, globalAES_ShortKey, globalAES_LongKey
    
    println("Plain Texts")
    printList(plainText)
    println("Cipher Texts")
    printList(hexaCipherText)
    
    println("Generating all keys")
    
    # Getting all the generated keys
    allHexaKeys, timeTaken = generateAllKeysBytes(3)
    
    print("All Keys generated")
    println("Total time taken for generating all the keys : " + str(timeTaken) + "s")
    
    println("Now trying to break AES")
    
    startTime = time.time()

    # key = "8e6330";
    # run from : 9288900
    result = loopForKeys(0, len(allHexaKeys))
    
    endTime = time.time()
    
    # Checking the result
    if result == 1:
        print("Total Time taken for breaking the AES is  : " + str(endTime - startTime) + "s")
    else:
        print("Not able to Break AES!")
    
    return result

# Function to get the special Message
def getSpecialMessage(hexaKey):
    global hexaCipherText
    
    byteKey = bytes.fromhex(hexaKey)
    expandedKey=expandKey(byteKey)
    specialHexaCipherText = hexaCipherText[4]
    specialByteCipherText = bytes.fromhex(specialHexaCipherText)
    
    print("Special Cipher Text : " + str(specialHexaCipherText))
    
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipherObject = Cipher(algorithms.AES(expandedKey), modes.CBC(IV))
    decryptorObject = cipherObject.decryptor()
    
    specialPlainText=decryptorObject.update(specialByteCipherText)+decryptorObject.finalize()
    
    print("$Secret Text : " + str(specialPlainText.decode()))
    
    return str(specialPlainText.decode())

# Function to save the file
def saveMessage(specialPlainText):
    f = open("aesSecretMessage.txt","w")
    f.write(specialPlainText + "\n")
    f.close()


# Main function
def main():
    global plainText, hexaCipherText, allHexaKeys, globalAES_ShortKey,globalAES_LongKey
    
    # Reading the plain texts
    textPath = "aesPlaintexts.txt"
    plainText = readFile(textPath)
    
    # reading the cipher Texts
    cipherPath = "aesCiphertexts.txt"
    hexaCipherText = readFile(cipherPath);
    
    result = breakCipher()
    
    if result == 1:
        print("The Short Key in Hexadecimal for AES : " + globalAES_ShortKey)
        println("The Short Key in Bytes AES : " + str(bytes.fromhex(globalAES_ShortKey))) 
        println("Now Getting the Special Message")
        specialPlainText = getSpecialMessage(globalAES_ShortKey)
        println("Now Saving Special Message")
        saveMessage(specialPlainText)
        println("Special Message Saved!")
    else:
        pass

# Calling main
if __name__ == '__main__':
    main()