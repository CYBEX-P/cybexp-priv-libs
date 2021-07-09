#!/usr/bin/env python3

import sys

sys.path.append("/priv-libs/libs")
from web_client import get_de_key, get_ore_key,get_ore_params, get_cpabe_pub_key, get_org_cpabe_secret
from cpabew import CPABEAlg
from de import RSADOAEP
from ORE import OREcipher

import pickle, json, yaml
import jsonlines
from tqdm import tqdm
import re
from dateutil import parser as t_parser
# from datetime import datetime
import traceback

from pprint import pprint



def load_yaml_file(f_name, verbose=False):
   with open(f_name) as f:
      if verbose:
         print("Loading data from {}...".format(f_name))
      data = yaml.load(f, Loader=yaml.FullLoader)
   return data

def load_json_file(f_name):
   with jsonlines.open(f_name) as reader:
      print("Loading data from {}...".format(f_name))
      dat = list()
      for line in tqdm(reader):
         dat.append(line["data"])
   return dat

def _to_bool(st):
   trues = ["t","true", "True"]
   try:
      if type(st) == bool :
         return st
      if type(st) == str and st in trues:
         return True
      else:
         False
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      return False

def _str_to_epoch(some_time_str):
   # parse dates without knwoing format
   # https://stackoverflow.com/a/30468539/12044480
   # print(some_time_str)
   t = t_parser.parse(some_time_str)
   unix = t.timestamp()
   # print("Time:", t, "unix:",unix)
   return int(unix)


# https://stackoverflow.com/questions/3640359/regular-expressions-search-in-list/39593126
def match_re_to_keys(reg: str, keys: list):
   r = re.compile(reg)
   newlist = list(filter(r.match, keys))
   # if len(newlist) > 0:
   #    print("reg: {}".format(repr(reg)))
   #    print("OG keys: {}".format(keys))
   #    print("matched keys [{}]: {}".format(repr(reg),newlist))
   return newlist


def encrypt_as_de(dat,key):
   try:
      enc_alg = RSADOAEP(key_sz_bits=2048, rsa_pem=key)
      dat = str(dat).encode("UTF-8")
      return enc_alg.encrypt(dat)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      traceback.print_exc()
      return None

# def encrypt_as_timestamp(dat,key): # old ORE lib
#    try:
#       if dat == None:
#          return None
#       if type(dat) != int:
#          dat = _str_to_epoch(dat)
#       if type(dat) == int and dat > 0:
#          return OREComparable.from_int(dat,key).get_cipher_obj().export()
#       else:
#          return None
#    except KeyboardInterrupt:
#       raise KeyboardInterrupt
#    except:
#       traceback.print_exc()
#       return None


def encrypt_as_timestamp(dat,key, params):
   try:
      if dat == None:
         return None
      if type(dat) != int:
         dat = _str_to_epoch(dat)
      if type(dat) == int and dat > 0:
         cipher = OREcipher(key, params)
         return cipher.encrypt(dat)
      else:
         return None
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      traceback.print_exc()
      return None


def encrypt_as_cpabe(dat, policy, pk):
   # global DEBUG_POLICY_PARCER
   # if DEBUG_POLICY_PARCER:
   #    return "CPABE_encrypted_{}".format(policy.replace(' ',"_"))
   # else:
   try:
      bsw07 = CPABEAlg()
      # data_to_enc = str(dat).encode("UTF-8")
      data_to_enc = pickle.dumps(dat)
      return bsw07.cpabe_encrypt_serialize(pk, data_to_enc, policy)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      traceback.print_exc()
      return None

def decrypt_cpabe(ciphertext, pk, sk):
   try:
      bsw07 = CPABEAlg()
      return bsw07.cpabe_decrypt_deserialize(pk, sk, ciphertext)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except Exception:
      # failed to decrypt
      return None
   except:
      traceback.print_exc()
      return None


def decrypt_record(record, pk, sk, debug=False):
   cpabe_keys = match_re_to_keys("cpabe_.*",record.keys())
   new_record = dict()
   for k in cpabe_keys:
      cipher = record[k]
      plain = pickle.loads(decrypt_cpabe(cipher, pk, sk))
      if plain:
         new_key = k[len("cpabe_"):]
         new_record[new_key] = plain
      elif debug:
         print("Failed to decrypt({}), wrong key for policy".format(k))

   return new_record

def load_fetch_de_key(kms_url,kms_access_key, DE_key_location, auth=None):
   try:
      with open(DE_key_location, "rb") as key_file: 
         k = key_file.read()
      return k
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         de_key = get_de_key(kms_url,kms_access_key, auth=auth)
         if de_key == None:
            sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
         with open(DE_key_location, "wb") as key_file:
            key_file.write(de_key)
         return de_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
   sys.exit("Could not load or fetch DE key")

def load_fetch_ore_key(kms_url,kms_access_key, ORE_key_location, auth=None):
   try:
      with open(ORE_key_location, "rb") as key_file: 
         k = key_file.read()
      return k
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_key = get_ore_key(kms_url,kms_access_key, auth=auth)
         if ore_key == None:
            sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
         with open(ORE_key_location, "wb") as key_file:
            key_file.write(ore_key)
         return ore_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
   sys.exit("Could not load or fetch ORE key")

def load_fetch_ore_params(kms_url,kms_access_key, ORE_params_location, auth=None):
   try:
      with open(ORE_params_location, "r") as key_file:
         k = json.load(key_file)
      return k
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_params = get_ore_params(kms_url,kms_access_key, auth=auth)
         if ore_params == None:
            sys.exit("Could not fetch ORE parameters from KMS server({})".format(kms_url))
         with open(ORE_params_location, "w") as key_file:
            json.dump(ore_params, key_file)
         return ore_params
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch ORE parameters from KMS server({})".format(kms_url))      
   sys.exit("Could not load or fetch ORE parameters")

def load_fetch_cpabe_pk(kms_url,kms_access_key, cpabe_pk_location, auth=None):
   cpabe_alg = CPABEAlg()
   try:
      with open(cpabe_pk_location, "rb") as key_file:
         k = cpabe_alg.deserialize_charm_obj(key_file.read())
      return k
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         pk_key = get_cpabe_pub_key(kms_url,kms_access_key,debug=True, auth=auth)
         if pk_key == None:
            sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
         with open(cpabe_pk_location, "wb") as key_file:
            key_file.write(cpabe_alg.serialize_charm_obj(pk_key))
         return pk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
   sys.exit("Could not load or fetch CPABE Public Key")

def load_fetch_cpabe_sk(kms_url, kms_access_key, cpabe_sk_location, auth=None):
   cpabe_alg = CPABEAlg()
   try:
      with open(cpabe_sk_location, "rb") as key_file:
         k = cpabe_alg.deserialize_charm_obj(key_file.read())
      return k
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         sk_key = get_org_cpabe_secret(kms_url,kms_access_key, auth=auth)
         if sk_key == None:
            sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
         with open(cpabe_sk_location, "wb") as key_file:
            key_file.write(cpabe_alg.serialize_charm_obj(sk_key))
         return sk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
   sys.exit("Could not load or fetch CPABE Secret Key")

def get_all_keys(kms_url, kms_access_key, DE_key_location, ORE_key_location,ORE_params_location, cpabe_pk_location, cpabe_sk_location=None, auth=None):
   keychain = {}

   keychain["de"] = load_fetch_de_key(kms_url,kms_access_key,DE_key_location, auth=auth)
   keychain["ore"] = load_fetch_ore_key(kms_url,kms_access_key,ORE_key_location, auth=auth)
   keychain["ore_params"] = load_fetch_ore_params(kms_url,kms_access_key,ORE_params_location, auth=auth)
   keychain["pk"] = load_fetch_cpabe_pk(kms_url,kms_access_key,cpabe_pk_location, auth=auth)

   if cpabe_sk_location: # allows to not fetch key when not wanted
      keychain["sk"] = load_fetch_cpabe_sk(kms_url,kms_access_key, cpabe_sk_location, auth=auth)

   return keychain
