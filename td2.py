import os
import binascii
import hashlib
import unicodedata
from tinyec.ec import SubGroup, Curve  #pip install tinyec
import hmac
import pickle


def random_seed() :
    
    '''
    binary_random_integer = ''
    random_integer = ''
    while len(binary_random_integer) != 128 :
        #1) Créer un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée 
        random_integer = os.urandom(16)
        #2) Représenter cette seed en binaire et le découper en lot de 11 bits 
        binary_random_integer = bin(int(random_integer.hex(), base=16))
    print("Random 128bits integer : {} ".format(random_integer))
    print("Random 128bits binary : ",binary_random_integer, len(binary_random_integer))    
    checksum = bin(int(hashlib.sha256(binary_random_integer.encode('utf-8')).hexdigest(),16))[2:6]
    print("Checksum :",checksum)
    entropy = str(binary_random_integer) +''+ str(checksum)
    print("Entropy :",entropy, len(entropy))
    return entropy[2:]'''

    random_integer = os.urandom(16) 
    entropy = binascii.hexlify(random_integer)   #"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"
    data = entropy.strip() #cleaning of data
    data = binascii.unhexlify(data)
    h = hashlib.sha256(data).hexdigest()
    b = bin(int(binascii.hexlify(data),16))[2:].zfill(len(data)*8) + bin(int(h,16))[2:].zfill(256)[: len(data)* 8//32]
    return b
    

def bits_tab(entropy) :
    map_bits = [] # List of list of bits
    for i in range(12):
        aux = []
        for j in range(11) :
            aux.append(entropy[i+j])
        map_bits.append(aux)
        aux = []
    return map_bits
    
def construct_english_dico()  :  
    #3) Attribuer à chaque lot un mot selon la liste BIP 39 et afficher la seed en mnémonique
    dico = {}
    file = open('english.txt','r')
    index = 0
    for line in file :
        if index != 2047 :
            dico[index] = line[:-1]
        else :
            dico[index] = line
        index+=1
    file.close()
    return dico

def construct_seed_from(dico, map_bits) : 
    seed = []
    for i in range(len(entropy)//11):
        indx = int(entropy[11*i:11*(i+1)],2)
        seed.append(english_dico[indx])
    return seed
    

def completion(word):
    while len(word) < 11 :
        word = '0'+word
    return word

def from_mnemonic_to_root_seed(seed, dico) :
    tab = []
    size = 0
    for word in seed :
        for key,value in dico.items() :
            if value == word :
                b = completion(bin(key)[2:])
                #print(b, key, value, word)
                tab.append(b)
                size += len(b)
    #print("Size and tab verification :",size,tab)
    return ''.join(tab)

def verify(word,dico):
    for key,value in dico.items() :
        if value == word :
            return True
    return False

def import_mnemonic_seed(dico) :
    seed = ['']*12
    for i in range(12):
        word = 1
        while verify(word, dico) == False :
            word = input("Word number {} : ".format(i+1))
            if not verify(word,dico): 
                print("This word doesn't exist, try again ...")
        seed[i] = word
    return seed

def hmac512(mnemonic) :
    mnemonic_bytes = unicodedata.normalize("NFKD",' '.join(mnemonic)).encode('utf-8')
    hmac512_hex = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, unicodedata.normalize("NFKD","mnemonic"+'').encode('utf-8'), 2048)[:64].hex()
    return hmac512_hex


def public_key_from_priv_key(private_key):    
    name = 'secp256k1'
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    a = 0x0000000000000000000000000000000000000000000000000000000000000000
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    g = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
         0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
    h = 1
    curve = Curve(a, b, SubGroup(p, g, n, h), name)
    #print('curve:', curve)
    
    privKey = int(private_key, 16)
    #print('privKey:', hex(privKey)[2:])
    pubKey = curve.g * privKey
    pubKeyCompressed = '0' + str(2 + pubKey.y % 2) + str(hex(pubKey.x)[2:])
    return pubKeyCompressed

def generate_child_keys(private_key, public_key, chain_key, i):
    ser_i = i.to_bytes(32, 'big').hex()
    ser_pk = str(int(private_key, 16).to_bytes(256, 'big'))
    if i >= 2^31:
        I = hmac.new(chain_key.encode(), ("0x00" + ser_pk + ser_i).encode(), digestmod='sha512')
    else:
        header = "0x02" if int(public_key, 16) % 2 == 0 else "0x03";
        I = hmac.new(chain_key.encode(), (header + ser_pk + ser_i).encode(), digestmod='sha512')
    tmp = I.hexdigest()
    IL = int(tmp[:len(tmp)//2], 16).to_bytes(32, 'big')
    IR = int(tmp[len(tmp)//2:], 16).to_bytes(32, 'big')

    return bin(int(IL, 16)) + (int(private_key, 16) % TODO), IR

if __name__ == '__main__':
    
    # If choix == Générer mnemonic 
    entropy = random_seed()
    bits_tap = bits_tab(entropy)
    english_dico = construct_english_dico()
    mnemonic = construct_seed_from(english_dico, bits_tap)
    print("Seed phrase (12 words) :",mnemonic) 
    
    
    #If choix == importer mnemonic (seed test : begin pen recall brand envelope stomach change unable unknown advance unknown enforce) 
    '''
    seed = import_mnemonic_seed(english_dico)
    print('Seed :', seed,'\n')
    root_seed = from_mnemonic_to_root_seed(seed, english_dico)
    '''
    
    #Master key private and chian code
    hmac512_hex = hmac512(mnemonic)
    #print(hmac512_hex)
    master_private_key, master_chain_code = hmac512_hex[:64], hmac512_hex[64:]
    master_public_key = public_key_from_priv_key(master_private_key)
    print("\nMaster private key :", master_private_key)
    print("Master chain code :", master_chain_code)
    print('Master public key :', master_public_key)

    # Generate child address
    generate_child_keys(master_private_key, master_public_key, master_chain_code, 0)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    