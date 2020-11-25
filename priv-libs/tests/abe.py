#!/usr/bin/env python
# coding: utf-8


import sys
sys.path.append("/priv-libs/libs")

import jsonlines
from tqdm import tqdm
from pprint import pprint

from cpabew import CPABEAlg
from cpabe_key_gen import gen_cpabe_master_keys, gen_cpabe_for_orgs

honeypot_testdata = []

print("Loading honeypot test data from files...")
with jsonlines.open('./tahoe-honeypot.jsonl') as reader:
    for line in tqdm(reader):
        honeypot_testdata.append(line["data"])




########### alternative initialization, use diff algorithm ##############
# waterr09 algorithm
# waters09 = CPABEAlg()
# waters09.alg = Waters09(waters09.group)
# waters09.hyb_abe = HybridABEnc(waters09.alg, waters09.group)
#########################################################################

# Define CP-ABE attributes for each test organization
org_abac_attributes = {
    "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
    "UNRRC": ["UNR", "ITOps", "Research"],
    "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
    "Public": ["Research"]
}

# Generate CP-ABE secret keys for each organization



cpabe_alg = CPABEAlg()
cpabe_alg_dec = CPABEAlg()

pk_mk = gen_cpabe_master_keys(cpabe_alg)
secret_keychain_bsw07 = gen_cpabe_for_orgs(cpabe_alg, pk_mk, org_abac_attributes)





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





# pprint(record)
print("=" * 50)
# ====================== WRITER - org A

cpabe_pubkey, cpabe_masterkey = pk_mk

plain = record["dest_ip"]

record["cpabe_dest_ip"] = cpabe_alg.cpabe_encrypt_serialize(
    cpabe_pubkey, 
    # plain.encode("UTF-8"),
    plain.encode(), 
    "UNR and ITOPS"
)

# record["cpabe_raw_dest_ip"] = cpabe_alg.cpabe_encrypt_raw(
#     cpabe_pubkey, 
#     plain.encode("UTF-8"), 
#     "UNR and ITOPS"
# )

# ======================== READER org b
#     "UNR-CISO": ["UNR", "SecEng", "IT-Ops", "CICI-Affiliate"],
import pickle

cpabe_secretkey = secret_keychain_bsw07["UNRCISO"]

cpabe_secretkey_wrong = secret_keychain_bsw07["UNRCSE"]


# ciphertext = record["cpabe_dest_ip"]

# open("enc_raw.bin", 'wb').write(cpabe_alg.serialize_charm_obj(record["cpabe_raw_dest_ip"]))
# ciphertext_r = cpabe_alg.deserialize_charm_obj(open("enc_raw.bin", 'rb').read())

open("enc.bin", 'wb').write(record["cpabe_dest_ip"])
ciphertext = open("enc.bin", 'rb').read()

# print("raw enc:", pickle.loads(ciphertext))
# print("\n")

dec_p = cpabe_alg_dec.cpabe_decrypt_deserialize(cpabe_pubkey, cpabe_secretkey, ciphertext).decode()
# dec_p = cpabe_alg.cpabe_decrypt_raw(cpabe_pubkey, cpabe_secretkey, ciphertext_r).decode()

# pprint(record)

print("dec_p:", dec_p)
print("og_p :",plain)

print("\n")
assert dec_p == plain, "Failed to decrypt! (decrypted incorrectly)"
print("it worked!!")


print("\ntesting decrypt with wrong keys")
try:
   dec_p_wrong = cpabe_alg_dec.cpabe_decrypt_deserialize(cpabe_pubkey, cpabe_secretkey_wrong, ciphertext).decode()
   sys.exit("it failed, decrypted when it shoulnt")
except Exception:
   print("passed")

# # In[19]:
# enc = RSADOAEP(2048)
# enc.encrypt(b"Hello")
# # In[31]:
# enc.encrypt(b"Headasdsally")