#!/usr/bin/env python
# coding: utf-8



# Generate CP-ABE secret keys for each organization

from de import RSADOAEP,AESSIV, AESCBC, AESCMC
import secrets

import jsonlines
from tqdm import tqdm
from pprint import pprint



#pswd_pemfile = secrets.token_bytes(16)
pswd_pemfile = b"f\x82\x1e)\xeb/\xf9\xe3\xc6\xdfZ\x16\xb9A\x11\x8e'=v\xfc\xefwA\xcfd\xdc\xcc\xa3\xccx'o"


class DEAlgorithm:
    def encrypt(self, msg: bytes) -> bytes:
        raise NotImplementedError




honeypot_testdata = []
print("Loading honeypot test data from files...")
with jsonlines.open('./tahoe-honeypot.jsonl') as reader:
    for line in tqdm(reader):
        honeypot_testdata.append(line["data"])



# by both parties
record = single_record_from_honeypot = honeypot_testdata[3]
# dat = record["src_ip"].encode("UTF-8")
dat = "Hello World".encode("UTF-8")

# party 1
print("=" * 25, "party 1", "="*25)
deterministic_encryption_algo = RSADOAEP(key_sz_bits=2048)
enc1 = deterministic_encryption_algo.encrypt(dat)
print(enc1)

k = deterministic_encryption_algo.export_key()
# pprint(record)



# party 2
print("=" * 25, "party 2", "="*25)

enc_alg = RSADOAEP(key_sz_bits=2048, rsa_k=k)
enc2 = enc_alg.encrypt(dat)
print(type(enc2))

print(enc2)

print("=" * 50)

assert enc1 == enc2, "Comp1 failed"
print("they equal :)")

enc3 = enc_alg.encrypt(b"Headasdsally")
assert enc1 != enc3, "comp2 failed"
assert enc2 != enc3, "comp3 failed"
print("they are not equal :)")
