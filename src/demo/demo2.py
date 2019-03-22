import os,time,sys,shutil,json
#from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,serialize,deserialize
#from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
#from charm.core.math.pairing import hashPair as extractor
#from charm.schemes.abenc.abenc_yang15 import CPabe_yang15
from util.scheme import Scheme
from util.common import print_byte_array,ct_to_dict,dict_to_ct,read_pt_from_file,\
    write_pt_to_file,write_ct_to_file,read_ct_from_file

if __name__== "__main__":

    # SET THE OUTPUT FOLDER
    if os.path.exists("outputs"):
        shutil.rmtree('outputs')
    os.makedirs('outputs')

    input_filename = 'testfile.md'
    cipher_filename = 'outputs/cipher.cpabe'
    output_filename = 'outputs/testfile_recovered.md'

    print("\n================= Setup ================\n")

    # DEFINE THE POLICY AND ATTRIBUTES
    attrs = ['ONE', 'TWO', 'THREE']
    attrs_p = ['FOUR', 'TWO']
    # access_policy = '((four or three) and (three or one))'
    access_policy = '(((four) or (three and one)) and two)'

    print("Attributes =>", attrs)
    print("Policy =>", access_policy)

    # SETUP CRYPTO CONFIGURATION (SS512 BY DEFAULT)
    scheme = Scheme()
    (cloud_pk, cloud_msk) = scheme.setup()

    ## START USER KEY PAIR GEN FOR U & CS
    pk_cs, sk_cs = scheme.keygen_user(cloud_pk, "cs")
    print("Cloud key pair =>", (pk_cs, sk_cs))

    pk_u, sk_u = scheme.keygen_user(cloud_pk, "alice")
    print("User key pair for Alice =>", (pk_u, sk_u))
    pk_u_ben, sk_u_ben = scheme.keygen_user(cloud_pk, "ben")
    print("User key pair for Ben =>", (pk_u_ben, sk_u_ben))

    ## START PROXY KEY PAIR GEN
    pxy_k_u = scheme.keygen_proxy(cloud_pk, cloud_msk, pk_u, pk_cs, attrs)
    print("Proxy key =>", pxy_k_u)
    pxy_k_u_ben = scheme.keygen_proxy(cloud_pk, cloud_msk, pk_u_ben, pk_cs, attrs_p)
    print("Proxy key =>", pxy_k_u_ben)

    # GENERATE SYMM (AES) KEY
    r = scheme.random_pair()
    print("Secret for file encryption (AES-CBC) bef extraction =>\n", r)

    # READ THE INPUT FILE CONTENT
    file_pt = read_pt_from_file(input_filename)

    print("\n============= Original Text =============\n")

    print_byte_array(file_pt[:15])
    print("...", end=" ")
    print("LENGTH OF ORIG FILE", len(file_pt))

    # BENCHMARKING: Measure how long the encryption/decryption takes.
    startTime = time.time()

    print("\n============ Encrypted Text =============\n")

    # ENCRYPT PLAIN TEXT FROM THE INPUT FILE
    file_ct = scheme.encrypt_text(file_pt, r)

    print("Encryption finished...")
    print("LENGTH OF ENC FILE", len(file_ct))

    print("\n============ Encrypted Key =============\n")

    # ENCRYPT THE SYMM KEY BY USING CPABE PAIRING-BASED ALGO

    secret_ct = scheme.encrypt_secret(r, cloud_pk, access_policy)
    print("\nEncrypt...\n", secret_ct)

    print("\n=========== Pack Cipher File ============\n")

    print("Enc. Key", secret_ct)
    print("Enc. File", file_ct)

    # SERIALIZE ALL PAIRING ELEMENTS INTO STRINGS AND WRITE TO FILE
    write_ct_to_file(file_ct, secret_ct, cipher_filename)

    print("\n=========== Read Cipher File ============\n")

    # READ THE ENCRYPTED FILE THAT SHARED ON THE PUBLIC ACCESSIBLE PLACE
    file_ct, key_ct_recovered = read_ct_from_file(cipher_filename)

    print("Load Enc. Key", key_ct_recovered)
    print("Load Enc. File", file_ct)

    print("\nCiphertext verification from input encrypted file:", key_ct_recovered == secret_ct)

    print("\n============ Decrypted Text =============\n")

    # PROXY DECRYPTS THE AES KEY FROM CPABE CIPHERTEXT
    intmed_value = scheme.decrypt_secret_proxy(key_ct_recovered, cloud_pk, sk_cs, pxy_k_u)
    intmed_value_ben = scheme.decrypt_secret_proxy(key_ct_recovered, cloud_pk, sk_cs, pxy_k_u_ben)
    print("Pxy Decrypt...")
    print("Intermediate decryption =>", intmed_value)
    print("Intermediate decryption =>", intmed_value_ben)

    # USER DECRYPTS THE AES KEY BY USING INTMD VALUE
    recovered_secret = scheme.decrypt_secret_user(intmed_value, cloud_pk, sk_u)
    recovered_secret_ben = scheme.decrypt_secret_user(intmed_value_ben, cloud_pk, sk_u_ben)
    print("\nUser Decrypt...")
    print("Recovered message =>", recovered_secret)
    print("Recovered message =>", recovered_secret_ben)

    print("\n============ Decrypted Text =============\n")

    # RECOVER THE AES SYMM ENCRYPTION CONFIGURATION
    rec_file_pt = scheme.decrypt_text(file_ct, recovered_secret)
    rec_file_pt_ben = scheme.decrypt_text(file_ct, recovered_secret_ben)

    print_byte_array(rec_file_pt[:15])
    print("...")
    print("\nLENGTH OF DEC FILE", len(rec_file_pt))
    print("\nLENGTH OF DEC FILE", len(rec_file_pt_ben))

    write_pt_to_file(rec_file_pt, output_filename)

    # DISPLAY THE FINAL OUTCOME
    if rec_file_pt == file_pt:
        print("Demonstration Succeeded!")
    else:
        print("Failure: inconsistence between the original and recovered msg")

    # DISPLAY THE BENCHMARKING RESULT
    totalTime = round(time.time() - startTime, 2)
    print('Elapsed time: %s seconds' % (totalTime))