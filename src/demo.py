import os,time,sys,shutil,json
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,serialize,deserialize
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from charm.schemes.abenc.abenc_yang15 import CPabe_yang15

group = PairingGroup("SS512")

def print_byte_array(arr):
    temp_int = 0
    for var in arr:
        temp_int += 1
        if temp_int % 16 == 0:
            print('{0:02x}'.format(var))
        else:
            print('{0:02x}'.format(var), end=" ")

def ct_to_dict(ct, group):
    if not isinstance(ct, dict):
        return None
    ct_serialized = {}
    for k in ct.keys():
        item = ct[k]
        if k in ['C', 'Cpp', 'C_tilde']:
            item_serialized = group.serialize(item).decode('utf-8')
            ct_serialized.update({k : item_serialized})
        elif isinstance(item, dict):
            sub_dict = {}
            for sub_k in item:
                sub_item = item[sub_k]
                sub_item_ser = group.serialize(sub_item).decode('utf-8')
                sub_dict.update({ sub_k : sub_item_ser})
            ct_serialized.update({k : sub_dict})
        else:
            ct_serialized.update({k: item})
    return ct_serialized

def dict_to_ct(ct_dict, group):
    if not isinstance(ct_dict, dict):
        return None
    recovered_ct = {}
    for k in ct_dict.keys():
        item = ct_dict[k]
        if k in ['C', 'Cpp', 'C_tilde']:
            item_deserialized = group.deserialize(item.encode('utf-8'))
            recovered_ct.update({k : item_deserialized})
        elif isinstance(item, dict):
            sub_dict = {}
            for sub_k in item:
                sub_item = item[sub_k]
                sub_item_des = group.deserialize(sub_item.encode('utf-8'))
                sub_dict.update({sub_k: sub_item_des})
            recovered_ct.update({k: sub_dict})
        else:
            recovered_ct.update({k : item})
    return recovered_ct

if __name__== "__main__":

    # SET THE OUTPUT FOLDER
    if os.path.exists("outputs"):
        shutil.rmtree('outputs')
    os.makedirs('outputs')

    inputFilename = 'testfile.md'
    cipherFilename = 'outputs/cipher.cpabe'
    outputFilename = 'outputs/testfile_recovered.md'
    cpabe = CPabe_yang15(group)

    print("\n================= Setup ================\n")

    # DEFINE THE POLICY AND ATTRIBUTES
    attrs = ['ONE', 'TWO', 'THREE']
    # access_policy = '((four or three) and (three or one))'
    access_policy = '((four) or (three and one))'

    print("Attributes =>", attrs)
    print("Policy =>", access_policy)

    # SETUP CRYPTO CONFIGURATION
    (cloud_pk, cloud_msk) = cpabe.setup()

    ## START USER KEY PAIR GEN FOR U & CS
    pk_cs, sk_cs = cpabe.keygen_user(cloud_pk)
    print("Cloud key pair =>", (pk_cs, sk_cs))

    pk_u, sk_u = cpabe.keygen_user(cloud_pk)
    print("User key pair =>", (pk_u, sk_u))

    ## START PROXY KEY PAIR GEN
    pxy_k_u = cpabe.keygen_proxy(cloud_pk, cloud_msk, pk_u, pk_cs, attrs)
    print("Proxy key =>", pxy_k_u)

    # GENERATE SYMM (AES) KEY
    r = group.random(GT)
    secret = extractor(r)
    print("Key for file encryption (AES-CBC) =>", secret)

    # READ THE INPUT FILE CONTENT
    fileObj = open(inputFilename, 'rb')
    file_pt = fileObj.read()
    fileObj.close()

    print("\n============= Original Text =============\n")

    print_byte_array(file_pt[:15])
    print("...", end=" ")
    print("LENGTH OF ORIG FILE", len(file_pt))

    # BENCHMARKING: Measure how long the encryption/decryption takes.
    startTime = time.time()

    print("\n============ Encrypted Text =============\n")

    # SETUP SYMM CRYPTO: by default algo is AES in CBC mode
    symcrypt = SymmetricCryptoAbstraction(secret)

    # ENCRYPT PLAIN TEXT FROM THE INPUT FILE
    file_ct = symcrypt.encrypt(file_pt)

    print("Encryption finished...")
    print("LENGTH OF ENC FILE", len(file_ct))

    print("\n============ Encrypted Key =============\n")

    # ENCRYPT THE SYMM KEY BY USING CPABE PAIRING-BASED ALGO
    aes_key_pt = r
    print("AES key to be encrypted =>", aes_key_pt)

    aes_key_ct = cpabe.encrypt(cloud_pk, aes_key_pt, access_policy)
    print("\nEncrypt...\n", aes_key_ct)

    # DEBUG & VALIDATE THE CIPHER TEXT
    group.debug(aes_key_ct)

    print("\n=========== Pack Cipher File ============\n")

    print("Enc. Key", aes_key_ct)
    print("Enc. File", file_ct)

    # SERIALIZE ALL PAIRING ELEMENTS INTO STRINGS AND WRITE TO FILE
    aes_key_ct_serialized = ct_to_dict(aes_key_ct, group)
    aes_key_ct_printable = json.dumps(aes_key_ct_serialized)

    print(aes_key_ct_printable)

    outputFileObj = open(cipherFilename, 'w')
    outputFileObj.write(file_ct)
    outputFileObj.write("\n")
    outputFileObj.write(aes_key_ct_printable)
    outputFileObj.close()

    print("\n=========== Read Cipher File ============\n")

    # READ THE ENCRYPTED FILE THAT SHARED ON THE PUBLIC ACCESSIBLE PLACE
    fileObj = open(cipherFilename, 'r')
    read_file_ct = fileObj.readline()
    read_aes_key_ct = eval(fileObj.read())
    fileObj.close()

    aes_key_ct_recovered = dict_to_ct(read_aes_key_ct, group)

    print("Load Enc. Key", aes_key_ct_recovered)
    print("Load Enc. File", read_file_ct)

    print("\nCiphertext verification from input encrypted file:", aes_key_ct_recovered == aes_key_ct)

    print("\n============ Decrypted Text =============\n")

    # PROXY DECRYPTS THE AES KEY FROM CPABE CIPHERTEXT
    intmed_value = cpabe.proxy_decrypt(cloud_pk, sk_cs, pxy_k_u, aes_key_ct_recovered)
    print("Pxy Decrypt...")
    print("Intermediate decryption =>", intmed_value)

    # USER DECRYPTS THE AES KEY BY USING INTMD VALUE
    recovered_aes_key = cpabe.user_decrypt(cloud_pk, sk_u, intmed_value)
    print("\nUser Decrypt...")
    print("Recovered message =>", recovered_aes_key)

    print("\n============ Decrypted Text =============\n")

    # RECOVER THE AES SYMM ENCRYPTION CONFIGURATION
    rec_secret = extractor(recovered_aes_key)
    rec_symcrypt = SymmetricCryptoAbstraction(rec_secret)

    rec_file_pt = rec_symcrypt.decrypt(read_file_ct)

    print_byte_array(rec_file_pt[:15])
    print("...")

    print("\nLENGTH OF DEC FILE", len(rec_file_pt))

    # OUTPUT THE RECOVERED FILE PLAINTEXT
    outputFileObj = open(outputFilename, 'wb')
    outputFileObj.write(bytes(rec_file_pt))
    outputFileObj.close()

    # DISPLAY THE FINAL OUTCOME
    if rec_file_pt == file_pt:
        print("Demonstration Succeeded!")
    else:
        print("Failure: inconsistence between the original and recovered msg")

    # DISPLAY THE BENCHMARKING RESULT
    totalTime = round(time.time() - startTime, 2)
    print('Elapsed time: %s seconds' % (totalTime))