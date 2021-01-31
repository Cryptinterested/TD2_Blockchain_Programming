import os
import binascii
import hashlib
import unicodedata
from tinyec.ec import SubGroup, Curve  # pip install tinyec
import hmac


def random_seed():
    """
    Generate random seed in bits
    :return: seed bits
    """
    random_integer = os.urandom(16)
    entropy = binascii.hexlify(random_integer)  # "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"
    data = entropy.strip()  # cleaning of data
    data = binascii.unhexlify(data)
    h = hashlib.sha256(data).hexdigest()
    b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + bin(int(h, 16))[2:].zfill(256)[
                                                                        : len(data) * 8 // 32]
    return b


def bits_tab(entropy):
    map_bits = []  # List of list of bits
    for i in range(12):
        aux = []
        for j in range(11):
            aux.append(entropy[i + j])
        map_bits.append(aux)
    return map_bits


def construct_english_dico():
    # 3) Attribuer à chaque lot un mot selon la liste BIP 39 et afficher la seed en mnémonique
    dico = {}
    file = open('english.txt', 'r')
    index = 0
    for line in file:
        if index != 2047:
            dico[index] = line[:-1]
        else:
            dico[index] = line
        index += 1
    file.close()
    return dico


def construct_seed_from(dico, map_bits):
    seed = []
    for i in range(len(entropy) // 11):
        indx = int(entropy[11 * i:11 * (i + 1)], 2)
        seed.append(english_dico[indx])
    return seed


def completion(word):
    while len(word) < 11:
        word = '0' + word
    return word


def verify(word, dico):
    for key, value in dico.items():
        if value == word:
            return True
    return False


def import_mnemonic_seed(dico):
    """
    Ask the user to enter his seed word by word
    :param dico: English dictionary
    :return: list of the 12 words
    """
    seed = [''] * 12
    for i in range(12):
        word = 1
        while not verify(word, dico):
            word = input("Word number {} : ".format(i + 1))
            if not verify(word, dico):
                print("This word doesn't exist, try again ...")
        seed[i] = word
    return seed


def hmac512(mnemonic):
    """
    Hmac function
    :param mnemonic: The mnemonic
    :return: 128 bits (private key + chain code)
    """
    mnemonic_bytes = unicodedata.normalize("NFKD", ' '.join(mnemonic)).encode('utf-8')
    hmac512_hex = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes,
                                      unicodedata.normalize("NFKD", "mnemonic" + '').encode('utf-8'), 2048)[:64].hex()
    return hmac512_hex


def public_key_from_priv_key(private_key):
    """
    Generate public key from a private key
    :param private_key: The address private key
    :return: public key
    """
    name = 'secp256k1'
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    a = 0x0000000000000000000000000000000000000000000000000000000000000000
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    g = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
         0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
    h = 1
    curve = Curve(a, b, SubGroup(p, g, n, h), name)

    privKey = int(private_key, 16)
    pubKey = curve.g * privKey
    pubKeyCompressed = '0' + str(2 + pubKey.y % 2) + str(hex(pubKey.x)[2:])
    return pubKeyCompressed


def generate_child_keys(private_key, public_key, chain_key, i):
    """
    To generate child keys
    :param private_key: The parent private key
    :param public_key: The parent public key
    :param chain_key: The parent chain key
    :param i: The index
    :return: child private key, child chain code
    """
    ser_i = i.to_bytes(32, 'big').hex()
    ser_pk = str(int(private_key, 16).to_bytes(256, 'big'))
    if i >= 2 ** 31:
        I = hmac.new(chain_key.encode(), ("0x00" + ser_pk + ser_i).encode(), digestmod='sha512')
    else:
        header = "0x02" if int(public_key, 16) % 2 == 0 else "0x03"
        I = hmac.new(chain_key.encode(), (header + ser_pk + ser_i).encode(), digestmod='sha512')
    tmp = I.hexdigest()
    IL = int(tmp[:len(tmp) // 2], 16).to_bytes(32, 'big')
    IR = int(tmp[len(tmp) // 2:], 16).to_bytes(32, 'big')

    return hex((int(IL.hex(), 16) + int(private_key, 16) % 2 ** 256))[2:], IR.hex()


def do_choice(options, prompt):
    """
    Ask to user to make choice by command line
    :param options:
    :param prompt:
    :return:
    """
    while True:
        output = input(prompt)
        if output in options:
            return output
        else:
            print("Bad option. Options: " + ", ".join(options))


if __name__ == '__main__':

    choice = do_choice(["0", "1"], "Entrez 0 pour générer une mnemonic, 1 pour l'importer : ")
    english_dico = construct_english_dico()

    # seed test : begin pen recall brand envelope stomach change unable unknown advance unknown enforce
    if choice == "1":  # Import mnemonic
        mnemonic = import_mnemonic_seed(english_dico)
    else:  # Generate mnemonic
        entropy = random_seed()
        bits_tap = bits_tab(entropy)
        mnemonic = construct_seed_from(english_dico, bits_tap)

    print("\nSeed phrase (12 words) :", mnemonic)
    # Master key private and chian code
    hmac512_hex = hmac512(mnemonic)
    master_private_key, master_chain_code = hmac512_hex[:64], hmac512_hex[64:]
    master_public_key = public_key_from_priv_key(master_private_key)
    print("\nMaster private key :", master_private_key)
    print("Master chain code :", master_chain_code)
    print('Master public key :', master_public_key)

    child_private_key = ""
    child_chain_code = ""
    choice2 = do_choice(["1", "2", "3"], "Entrez 1 pour générer une clé enfant, 2 pour générer une clé enfant à un "
                                         "index donné, 3 pour générer l'enfant d'index M de l'index N :")
    if choice2 == "1":
        child_private_key, child_chain_code = generate_child_keys(master_private_key, master_public_key,
                                                                  master_chain_code, 0)
        print("\nChild private key :", child_private_key)
        print("Child chain code :", child_chain_code)
    elif choice2 == "2":
        index = -1
        while index < 0:
            try:
                index = int(input("Choisissez un index : "))
                child_private_key, child_chain_code = generate_child_keys(master_private_key, master_public_key,
                                                                          master_chain_code, index)
                print("Génération de l'enfant à l'index", index)
                print("\nChild private key :", child_private_key)
                print("Child chain code :", child_chain_code)
                break
            except:
                print("Saisissez un entier positif !")
    else:
        succed = False
        while not succed:
            try:
                # Level 1
                level1 = int(input("Choisissez l'index de la couche 1 : "))
                child_private_key1, child_chain_code1 = generate_child_keys(master_private_key, master_public_key,
                                                                            master_chain_code, level1)
                child_public_key1 = public_key_from_priv_key(child_private_key1)

                # Level 2
                level2 = int(input("Choisissez l'index de la couche 2 : "))
                child_private_key2, child_chain_code2 = generate_child_keys(child_private_key1, child_public_key1,
                                                                            child_chain_code1, level2)
                child_public_key2 = public_key_from_priv_key(child_private_key2)

                print("\nChild private key :", child_private_key2)
                print("Child chain code :", child_chain_code2)
                succed = True
            except:
                print("Saisissez un entier positif !")
