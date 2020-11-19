#!/usr/bin/env python
# coding: utf-8


import sys
sys.path.append("/priv-libs/libs")

from cpabew import CPABEAlg
import jsonlines
# from tqdm import tqdm
from pprint import pprint






# from Crypto.Cipher import AES
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.PublicKey import RSA
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import padding, serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from hashlib import blake2b
# import secrets
# from typing import Optional





def load_cpabe_master_keys(cpabe_alg,
                mk_path = "/secrets/cpabe-mk.binary",
                pk_path = "/secrets/cpabe-pk.binary", pub_only=False):

    algname = cpabe_alg.alg.__class__.__name__

    mk = cpabe_alg.deserialize_charm_obj(open(mk_path, 'rb').read())
    pk = cpabe_alg.deserialize_charm_obj(open(pk_path, 'rb').read())
    
    print(f"Loaded pubkey and masterkey from files ({algname})")
    if pub_only:
        return pk
    return (pk,mk)


def _gen_cpabe_master_keys(cpabe_alg,mk_path,pk_path):
    algname = cpabe_alg.alg.__class__.__name__
    pk, mk = cpabe_alg.hyb_abe.setup()
    if algname == "CPabe09":
        pk, mk = mk, pk # setup result tuple is reversed 
                
    print(f"Generated new KMS keys for {algname}")

    open(mk_path, 'wb').write(cpabe_alg.serialize_charm_obj(mk))
    print(f"Saved {algname} master key to {mk_path}")
    open(pk_path, 'wb').write(cpabe_alg.serialize_charm_obj(pk))
    print(f"Saved {algname} public key to {pk_path}")
    return (pk, mk)

def gen_cpabe_master_keys(cpabe_alg, force=False,
                mk_path = "/secrets/cpabe-mk.binary",
                pk_path = "/secrets/cpabe-pk.binary"):
    
    algname = cpabe_alg.alg.__class__.__name__

    try:
        if force:
            return _gen_cpabe_master_keys(cpabe_alg,mk_path,pk_path)
        
        print(f"Checking existance of keys ({algname})")
        return load_cpabe_master_keys(cpabe_alg)

    except FileNotFoundError:
        return _gen_cpabe_master_keys(cpabe_alg,mk_path,pk_path)
    return None
    


def load_cpabe_org_secret_key(cpabe_alg,key_path):
    sk = cpabe_alg.deserialize_charm_obj(open(key_path, 'rb').read())
    print(f"Loaded key from {key_path}.")
#             print(cpabe_alg.hyb_abe.properties['scheme'].__dict__)
#             print(mk)
    return sk


def _gen_cpabe_org_secret_key(cpabe_alg, pk_mk, org_name, org_attributes,key_path):
    pk, mk = pk_mk
    algname = cpabe_alg.alg.__class__.__name__
    sk = cpabe_alg.hyb_abe.keygen(pk, mk, org_attributes)
    print(f"Generated new {algname} keys for {org_name} with {org_attributes}...   ")    
    open(key_path, 'wb').write(cpabe_alg.serialize_charm_obj(sk))
    print(f"\tSaved to {key_path}!")
    return sk


def load_cpabe_org_secret_key_from_name(cpabe_alg, org_name):
    algname = cpabe_alg.alg.__class__.__name__
    key_path = f"/secrets/cpabe-sk-{algname}-{org_name}.binary"
    return load_cpabe_org_secret_key(cpabe_alg, key_path)

def gen_cpabe_org_secret_key(cpabe_alg, pk_mk, org_name, org_attributes,force=False,key_path=None):
    algname = cpabe_alg.alg.__class__.__name__

    if not key_path:
        key_path = f"/secrets/cpabe-sk-{algname}-{org_name}.binary"
    try:
        if force:
            return _gen_cpabe_org_secret_key(cpabe_alg, pk_mk, org_name, org_attributes,key_path)
        return load_cpabe_org_secret_key(cpabe_alg, key_path)
    except FileNotFoundError:
        return _gen_cpabe_org_secret_key(cpabe_alg, pk_mk, org_name, org_attributes,key_path)

    return None

def gen_cpabe_for_orgs(cpabe_alg, pk_mk, org_attributes):
    # Generate CP-ABE secret keys for each organization in the list
    keychain = {}
    for org, atrib_list in org_attributes.items():
        sk = gen_cpabe_org_secret_key(cpabe_alg, pk_mk, org,atrib_list)
        keychain[org] = sk
        if not sk:
            print("Failed to generate secret cpabe key for {}".format(org))

    return keychain






def test_main_cpabe():
    bsw07 = CPABEAlg()

    # Define CP-ABE attributes for each test organization
    org_abac_attributes = {
        "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
        "UNRRC": ["UNR", "ITOps", "Research"],
        "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
        "Public": ["Research"]
    }

    pk_mk = gen_cpabe_master_keys(bsw07)
    
    cpabe_pubkey = pk_mk[0] # <--- used for encryption
    cpabe_masterkey = pk_mk[1]# <-- key generation

    if pk_mk:
        secret_keychain = gen_cpabe_for_orgs(bsw07, pk_mk, org_abac_attributes)
    else:
        secret_keychain = None

    return bsw07, pk_mk, secret_keychain

if __name__ == '__main__':

    print("Testing cpabe key creation/loading")
    res = test_main_cpabe()
    assert all(res), "Failed"
    print("Passed")
    


