import os
import binascii
import hashlib


binary_random_integer = ''
random_integer = ''

while len(binary_random_integer) != 128 :

    #1) Créer un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée 
    random_integer = os.urandom(16)
    #2) Représenter cette seed en binaire et le découper en lot de 11 bits 
    binary_random_integer = bin(int(random_integer.hex(), base=16)).lstrip('0b')
    

print("Random 128bits integer : {} ".format(random_integer))
print("Random 128bits binary : ",binary_random_integer, len(binary_random_integer))    

checksum = bin(int(hashlib.sha256(binary_random_integer.encode('utf-8')).hexdigest(),16))[2:6]
print("Checksum :",checksum)

entropy = str(binary_random_integer) +''+ str(checksum)
print("Entropy :",entropy, len(entropy))

segmentation = [[elt[i+j] for i,elt in enumerate(entropy)] for j in range(11)]
print(segmentation)
