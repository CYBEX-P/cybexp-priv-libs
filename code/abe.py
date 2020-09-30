#!/usr/bin/env python
# coding: utf-8




from cpabew import CPABEAlg
import jsonlines
from tqdm import tqdm
from pprint import pprint


honeypot_testdata = []

print("Loading honeypot test data from files...")
with jsonlines.open('./tahoe-honeypot.jsonl') as reader:
    for line in tqdm(reader):
        honeypot_testdata.append(line["data"])



bsw07 = CPABEAlg()

# waterr09 algorithm
# waters09 = CPABEAlg()
# waters09.alg = Waters09(waters09.group)
# waters09.hyb_abe = HybridABEnc(waters09.alg, waters09.group)

# Define CP-ABE attributes for each test organization
org_abac_attributes = {
    "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
    "UNRRC": ["UNR", "ITOps", "Research"],
    "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
    "Public": ["Research"]
}

# Generate CP-ABE secret keys for each organization






from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import blake2b
import secrets
from typing import Optional


pswd_pemfile = b"f\x82\x1e)\xeb/\xf9\xe3\xc6\xdfZ\x16\xb9A\x11\x8e'=v\xfc\xefwA\xcfd\xdc\xcc\xa3\xccx'o"


class DEAlgorithm:
    def encrypt(self, msg: bytes) -> bytes:
        raise NotImplementedError


def rsa_key(key_sz: int = 2048, pswd_pemfile: Optional[str] = None):
    """
    Generate an RSA key in PEM format.

    :param key_sz bits for key size. Recommended is >=2048
    :param pswd_pemfile passphrase for RSA key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_sz, backend=default_backend()
    )

    if pswd_pemfile:
        keyenc_alg = serialization.BestAvailableEncryption(password=pswd_pemfile)
    else:
        keyenc_alg = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=keyenc_alg,
    )

    return RSA.importKey(pem, passphrase=pswd_pemfile)


class RSADOAEP(DEAlgorithm):
    def __init__(self, key_sz_bits: int):
        # Use PKCS-OAEP cipher mode for RSA. Maximum plaintext size has to fit into modulus size.
        self.cipher = PKCS1_OAEP.new(rsa_key(key_sz_bits))
        self.name = f"RSA-DOAEP-{key_sz_bits}"

    def encrypt(self, msg: bytes) -> bytes:
        # Padding is a hash of the plaintext -- hence, deterministic
        self.cipher._randfunc = lambda n: blake2b(msg, digest_size=n).digest()
        ciphertext = self.cipher.encrypt(msg)
        return ciphertext







def cpabe_keys_by_org(cpabe_alg, org_attributes):
    global kms_keychain
    
    algname = cpabe_alg.alg.__class__.__name__
    
    print(f"Getting keys for CP-ABE ({algname})")

    mk_path = f"/secrets/cpabe-mk-{algname}.binary"
    pk_path = f"/secrets/cpabe-pk-{algname}.binary"

    try:
        mk = cpabe_alg.deserialize_charm_obj(open(mk_path, 'rb').read())
        pk = cpabe_alg.deserialize_charm_obj(open(pk_path, 'rb').read())
        
        print(f"Loaded pubkey and masterkey for {algname}")

    except FileNotFoundError:

        pk, mk = cpabe_alg.hyb_abe.setup()
        if algname == "CPabe09":
            pk, mk = mk, pk # lol, setup result tuple is reversed 
            
        print(f"Generated new KMS keys for {algname}")

        open(mk_path, 'wb').write(cpabe_alg.serialize_charm_obj(mk))
        print(f"Saved {algname} master key to {mk_path}")
        open(pk_path, 'wb').write(cpabe_alg.serialize_charm_obj(pk))
        print(f"Saved {algname} public key to {pk_path}")
    
    kms_keychain[algname] = (pk, mk)

    keychain = {}
    for org, cpabe_attrlist in org_attributes.items():
        key_path = f"/secrets/cpabe-sk-{algname}-{org}.binary"
        try:
            sk = cpabe_alg.deserialize_charm_obj(open(key_path, 'rb').read())
            print(f"Loaded {algname} key for {org} ({key_path}).")
#             print(cpabe_alg.hyb_abe.properties['scheme'].__dict__)
#             print(mk)
        except FileNotFoundError:
            sk = cpabe_alg.hyb_abe.keygen(pk, mk, cpabe_attrlist)
            print(f"Generated new {algname} keys for {org} with {cpabe_attrlist}...   ")    
            open(key_path, 'wb').write(cpabe_alg.serialize_charm_obj(sk))
            print(f"\tSaved to {key_path}!")
        keychain[org] = sk
    return keychain

kms_keychain = {}            
secret_keychain_bsw07 = cpabe_keys_by_org(bsw07, org_abac_attributes)


cpabe_pubkey, cpabe_masterkey = kms_keychain['CPabe_BSW07']
cpabe_pubkey # <--- used for encryption
cpabe_masterkey # <-- key generation




cpabe_alg = CPABEAlg()


record = single_record_from_honeypot = honeypot_testdata[3]


# # pprint(record)
# print("=" * 50)
# # ====================== WRITER - org A


# record["cpabe_dest_ip"] = cpabe_alg.cpabe_encrypt(
#     cpabe_pubkey, 
#     record["dest_ip"].encode("UTF-8"), 
#     "UNR and ITOPS"
# )

# # ======================== READER org b
# #     "UNR-CISO": ["UNR", "SecEng", "IT-Ops", "CICI-Affiliate"],
# import pickle

# cpabe_secretkey = secret_keychain_bsw07["UNRCISO"]
# ciphertext = record["cpabe_dest_ip"]
# print(pickle.loads(ciphertext))

# dec_p =cpabe_alg.cpabe_decrypt(cpabe_pubkey, cpabe_secretkey, ciphertext).decode()

# print("dec_p:", dec_p)
# print("og_p :",record["dest_ip"])

# assert dec_p == record["dest_ip"], "Failed to decrypt!"
# print("it worked!!")




deterministic_encryption_algo = RSADOAEP(key_sz_bits=2048)

# pprint(record)
print("=" * 50)
# ====================== WRITER - org A
record["i_src_ip"] = deterministic_encryption_algo.encrypt(record["src_ip"].encode("UTF-8"))

cpabe_pubkey, cpabe_masterkey = kms_keychain['CPabe_BSW07']

plain = record["dest_ip"]

record["cpabe_dest_ip"] = cpabe_alg.cpabe_encrypt_serialize(
    cpabe_pubkey, 
    plain.encode("UTF-8"), 
    "UNR and ITOPS"
)

record["cpabe_raw_dest_ip"] = cpabe_alg.cpabe_encrypt_raw(
    cpabe_pubkey, 
    plain.encode("UTF-8"), 
    "UNR and ITOPS"
)

# ======================== READER org b
#     "UNR-CISO": ["UNR", "SecEng", "IT-Ops", "CICI-Affiliate"],
import pickle

cpabe_secretkey = secret_keychain_bsw07["UNRCISO"]
#cpabe_secretkey = secret_keychain_bsw07["UNRCSE"]


# ciphertext = record["cpabe_dest_ip"]

open("enc_raw.bin", 'wb').write(cpabe_alg.serialize_charm_obj(record["cpabe_raw_dest_ip"]))
ciphertext_r = cpabe_alg.deserialize_charm_obj(open("enc_raw.bin", 'rb').read())

# open("enc.bin", 'wb').write(record["cpabe_dest_ip"])
# ciphertext = open("enc.bin", 'rb').read()

# print("raw enc:", pickle.loads(ciphertext))
# print("\n")

# dec_p = cpabe_alg.cpabe_decrypt_deserialize(cpabe_pubkey, cpabe_secretkey, ciphertext).decode()
dec_p = cpabe_alg.cpabe_decrypt_raw(cpabe_pubkey, cpabe_secretkey, ciphertext_r).decode()

# pprint(record)

print("dec_p:", dec_p)
print("og_p :",plain)

print("\n")
assert dec_p == plain, "Failed to decrypt! (decrypted incorrectly)"
print("it worked!!")


# # In[19]:
# enc = RSADOAEP(2048)
# enc.encrypt(b"Hello")
# # In[31]:
# enc.encrypt(b"Headasdsally")