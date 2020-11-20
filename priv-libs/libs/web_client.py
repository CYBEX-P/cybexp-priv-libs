#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")

import requests
from pprint import pprint
import traceback
import pickle

from cpabew import CPABEAlg
from ORE import ORESecretKey

backend_api_base = "http://localhost:5001"
kms_api_base = "http://localhost:5002"



def get_de_key(kms_api_base, debug=False):
   try:
      r = requests.get(url=kms_api_base+"/get/key/de")
      raw_key = r.content

      return raw_key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def get_ore_key(kms_api_base, debug=False):
   try:
      r = requests.get(url=kms_api_base+"/get/key/ore")
      raw_key = r.content
      key = ORESecretKey.from_raw_bytes(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def get_cpabe_pub_key(kms_api_base, debug=False):

   try:
      bsw07 = CPABEAlg()
      r = requests.get(url=kms_api_base+"/get/key/cpabe-pk")
      raw_key = r.content
      key = bsw07.deserialize_charm_obj(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None




def get_org_cpabe_secret(kms_api_base, name, debug=False):
   try:
      bsw07 = CPABEAlg()
      req_body = {"name": name}
      r = requests.get(url=kms_api_base+"/get/key/cpabe-sk", json=req_body)
      raw_key = r.content
      key = bsw07.deserialize_charm_obj(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None


def post_enc_data(base_url,data, debug=False):  
   try:
      if type(data["index"]) != list or len(data)<=0:
         return None
      ser_data = pickle.dumps(data)
      r = requests.post(url=base_url+"/add/enc-data",
                          data=ser_data,
                          headers={'Content-Type': 'application/octet-stream'})
      
      if r.status_code >= 300:
         return False
      return True

   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return False

def query_enc_data(base_url, val=None, left_epoch=None, right_epoch=None, debug=False):
   pass

   