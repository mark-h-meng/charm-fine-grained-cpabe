from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction, SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

group = PairingGroup("SS512")

msg = b"This is a secret message that is larger than the group elements and has to be encrypted symmetrically"
print("original msg\n", msg)

r = group.random(G1)
print("random num\n", r)

# key = extractor(r)
key = extract_key(r)
print("symmetric key\n", key)

symcrypt = SymmetricCryptoAbstraction(key) # or SymmetricCryptoAbstraction without authentication
# by default algo is AES in CBC mode

# encryption
ciphertext = symcrypt.encrypt(msg)
print("ciphertext\n", ciphertext)

# decryption
recoveredMsg = symcrypt.decrypt(ciphertext)
print("recovered msg\n", recoveredMsg)

assert msg == recoveredMsg