# Importing all the required libraries
import os,binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen16 import *
import time
import threading
from ast import Bytes

# variable for storing all the plain text
plainText = []
# variable for storing all the hexadecimal cipher text
hexaCipherText = []
# variable for storing all the byte keys
allByteKeys = []
# Set for storing all the cipher texts
allFirstCipherSet = set()
allFirstCipherDashSet = set()
# Dictionaries for storing all the cipher texts
allFirstCipherDict = {}
allFirstCipherDashDict = {}

# Function for printing with the next line
def println(object):
    print(object)
    print()

# Function for printing the list
def printList(l):
    loop = 0
    for content in l:
        loop += 1
        print(f"{loop}. {content}")
    print()

# Function for reading the file
def readFile(path):
    l = []
    f = open(path,"r")
    for line in f:
        l.append(line.rstrip())
    
    return l

# Function for generating all the keys of desired bytes
def generateAllKeysBytes(sizeInBytes):
    allKeys = []
    
    start = time.time()
    
    # generating all the keys of desired length
    for oneKey in range(2**16):
        byteKey = oneKey.to_bytes(sizeInBytes, byteorder = 'big')
        allKeys.append(byteKey)

    end = time.time()
    totalTime = end - start
    
    return allKeys, totalTime

# Function for making the Cipher object
def makeCipherObject(shortKeyBytes):
    shortKeyHex = shortKeyBytes.hex()
        
    shortKey = bytearray(shortKeyBytes)
    
    longKey = expandKey(shortKey)
    
    IV=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    
    cipherObject = Cipher(algorithms.AES(longKey), modes.CBC(IV))
    
    return cipherObject

# Function for encrypting through AES
def encryptAES(cipherObject,textMessage):
    byteMessage = textMessage.encode('UTF-8')
    encryptor = cipherObject.encryptor()
    cipherText = encryptor.update(byteMessage) + encryptor.finalize()
    return cipherText 

# Function for decrypting with DES
def decryptAES(cipherObject,hexaMessage):
    byteMessage = bytes.fromhex(hexaMessage)
    decryptor = cipherObject.decryptor()
    byteReturnMessage = decryptor.update(byteMessage) + decryptor.finalize()
    return byteReturnMessage


# Function for verifying the keys
def verifyKey(keyTuple):
    global plainText, hexaCipherText
    
    # Getting the values from the key tuple
    shortKey1Bytes = keyTuple[0]
    shortKey2Bytes = keyTuple[1]
    
    # Making the cipher object
    cipherObject_1 = makeCipherObject(shortKey1Bytes)
    cipherObject_2 = makeCipherObject(shortKey2Bytes)
    
    matchFound = 0
    
    # Checking for every message
    for i in range(0,4):
        ct = encryptAES(cipherObject_1, plainText[i])
        ctDash = decryptAES(cipherObject_2, hexaCipherText[i])
        
        if ct.hex() == ctDash.hex():
            matchFound += 1 
    
    # If all the matches are correct then return 1 else 0
    if matchFound == 4:
        return 1
    else:
        return 0
    
# Function for saving all the cipher texts
def saveCipher(i):
    global allByteKeys,plainText, hexaCipherText, allFirstCipherSet, allFirstCipherDashSet,allFirstCipherDict, allFirstCipherDashDict
    
    # Getting the text message and corresponding hexadecimal cipher text
    textMessage = plainText[3]  # String
    secondCipher = hexaCipherText[3]  # Hexadecimal
    
    # Getting the byte key
    shortKeyBytes = allByteKeys[i]
    shortKeyHex = shortKeyBytes.hex()
    
    # print("Encrypting, Decrypting and Saving for Key : [" + str(shortKeyBytes.hex()) + "]")
    
    cipherObject = makeCipherObject(shortKeyBytes)
    
    # Encrypting using AES from one side
    cipherText = encryptAES(cipherObject, textMessage)
    
    # Decrypting using AES from other side
    cipherTextDash = decryptAES(cipherObject, secondCipher)
    cipherTextHex = cipherText.hex()
    cipherTextDashHex = cipherTextDash.hex()
    
    # Adding all the results in sets and dictionaries
    allFirstCipherSet.add(cipherTextHex)
    allFirstCipherDashSet.add(cipherTextDashHex)
    
    allFirstCipherDict[cipherTextHex] = shortKeyHex
    allFirstCipherDashDict[cipherTextDashHex] = shortKeyHex
    
# Utility Function for breaking the cipher text
def breakCipher_Util():
    global allByteKeys, plainText, allFirstCipherSet, allFirstCipherDashSet,allFirstCipherDict, allFirstCipherDashDict
    
    byteKeyList = []
    hexKeyList = []
    
    println("Now trying to break AES")
    
    # For every element in one set check if it is present in other set or not
    for ct1 in allFirstCipherSet:
        # print("Trying for cipher text number : " + str(loop))
        if ct1 in allFirstCipherDashSet:
            # Get the keys
            key1 = allFirstCipherDict[ct1]
            key2 = allFirstCipherDashDict[ct1]
            
            print("Match Found!")
            println("Keys in hex : [" + str(key1) + ", " + str(key2) + "]")
            println("Keys in Bytes : [" + str(bytes.fromhex(key1)) + ", " + str(bytes.fromhex(key2)) + "]")
            
            # Append them to list
            hexKeyList.append((key1,key2))
            byteKeyList.append((bytes.fromhex(key1), bytes.fromhex(key2)))
    
    return hexKeyList, byteKeyList

# Function for saving the messages
def saveMessage(specialPlainText):
    f = open("2aesSecretMessage.txt","w")
    f.write(specialPlainText + "\n")
    f.close()

# Function for getting the special message
def getSpecialMessage(keyTuple):
    global hexaCipherText
        
    shortKey1Bytes = keyTuple[0]
    shortKey2Bytes = keyTuple[1]
    
    # Making cipher object
    cipherObject_1 = makeCipherObject(shortKey1Bytes)
    cipherObject_2 = makeCipherObject(shortKey2Bytes)
    
    # First decrypt using AES
    ct1 = decryptAES(cipherObject_2, hexaCipherText[-1])
    # Again decrypt using AES
    specialPlainText = decryptAES(cipherObject_1, ct1.hex())

    println("The Special Message is : " + str(specialPlainText.decode()))
    
    return str(specialPlainText.decode())

# Function for breaking the cipher text
def breakCipher():
    global allByteKeys, plainText
    
    # Generating all possible keys
    println("Generating All Possible keys!")
    allByteKeys, timeTaken = generateAllKeysBytes(2)
    print("All keys Generated!")
    println("Total time taken for generating all the keys : " + str(timeTaken) + "s")
    
    startTime = time.time()
    
    # Saving all possible cipher texts will all the keys
    for i in range(0,len(allByteKeys)):
        saveCipher(i)
    
    # Getting result
    hexKeyList, byteKeyList = breakCipher_Util()

    endTime = time.time()

    # If there is at least one key then verify it
    if len(hexKeyList) > 0:
        println("Match Found!")
        print("Keys : ")
        printList(hexKeyList)
        print("Now verifying Keys...")
    else:
        print("Not able to Break AES!")
        return
    
    res = 0
    
    # Tuple for storing the final key pair
    byteKeyTuple = ()
        
    for i in range(0,len(byteKeyList)):
        res = verifyKey(byteKeyList[i])
        if res == 1:
            byteKeyTuple = byteKeyList[i]
            break
    
    # If res == 1 then verification successfull
    if res == 1:
        print("Key Verified Successfully!")
        print("Verified key Pair in Hex : [" + str(byteKeyTuple[0].hex()) + ", " + str(byteKeyTuple[1].hex()) + "]")
        print("Verified key Pair in Bytes : " + str(byteKeyTuple))
        println("Total Time taken for breaking the AES is  : " + str(endTime - startTime) + "s")
        println("Now getting the special Message")
        specialMessage = getSpecialMessage(byteKeyTuple)
        println("Now Saving this message")
        saveMessage(specialMessage)
        print("Message Saved!")
    else:
        print("Problem in key verification!\nNot able to Break AES!")


# Main Function
def main():
    global plainText, hexaCipherText
    
    # Reading the plain texts
    textPath = "2aesPlaintexts.txt"
    plainText = readFile(textPath)
    
    # Reading the cipher texts
    cipherPath = "2aesCiphertexts.txt"
    hexaCipherText = readFile(cipherPath);
    
    print("Plain Texts:-")
    printList(plainText)
    
    print("Cipher Texts:-")
    printList(hexaCipherText)
    
    # Calling function for breaking the cipher texts
    breakCipher()
    
# Calling Main
if __name__ == '__main__':
    main()