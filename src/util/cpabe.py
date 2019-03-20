from charm.schemes.abenc.abenc_yang15 import CPabe_yang15
from charm.toolbox.pairinggroup import PairingGroup, GT

groupObj = PairingGroup('SS512')
cpabe = CPabe_yang15(groupObj)

attrs = ['ONE', 'TWO', 'THREE']
access_policy = '((four or three) and (three or one))'

print("Attributes =>", attrs)
print("Policy =>", access_policy)

(pk, mk) = cpabe.setup()

# sk = cpabe.keygen(pk, mk, attrs)

## START KEY GEN FOR USER & CS
pk_cs, sk_cs = cpabe.keygen_user(pk)
print("\ncloud key pair =>", (pk_cs, sk_cs))

pk_u, sk_u = cpabe.keygen_user(pk)
print("\nuser key pair =>", (pk_u, sk_u))

pxy_k_u = cpabe.keygen_proxy(pk, mk, pk_u, pk_cs, attrs)
print("\nproxy key =>", pxy_k_u)

rand_msg = groupObj.random(GT)
print("\nmsg =>", rand_msg)
ct = cpabe.encrypt(pk, rand_msg, access_policy)
print("\nEncrypt...\n", ct)
groupObj.debug(ct)

intmed_value = cpabe.proxy_decrypt(pk, sk_cs, pxy_k_u, ct)
print("\nPxy Decrypt...\n")
print("\nIntm msg =>", intmed_value)

rec_msg = cpabe.user_decrypt(pk, sk_u, intmed_value)
print("\nUser Decrypt...\n")
print("\nRec msg =>", rec_msg)

result = (rand_msg == rec_msg)

if result:
    print("\nSuccessful Decryption!!!")
else:
    print("\nFAILED Decryption: message is incorrect")
## END
