#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")

import requests
from pprint import pprint
import traceback
import pickle

from cpabew import CPABEAlg
from ORE import ORESecretKey


def get_de_key(kms_api_base,token ,auth=None, debug=False):
   if type(token) != str:
      return None

   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      r = requests.get(url=kms_api_base+"/get/key/de", headers=hed, **kw_auth)
      raw_key = r.content

      return raw_key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def get_ore_key(kms_api_base,token, auth=None, debug=False):
   if type(token) != str:
      return None

   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      r = requests.get(url=kms_api_base+"/get/key/ore", headers=hed, **kw_auth)
      raw_key = r.content
      key = ORESecretKey.from_raw_bytes(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def get_cpabe_pub_key(kms_api_base,token, auth=None, debug=False):
   if type(token) != str:
      return None

   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      bsw07 = CPABEAlg()
      r = requests.get(url=kms_api_base+"/get/key/cpabe-pk", headers=hed, **kw_auth)
      raw_key = r.content
      key = bsw07.deserialize_charm_obj(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None




def get_org_cpabe_secret(kms_api_base,token, auth=None, debug=False):
   if type(token) != str:
      return None

   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      bsw07 = CPABEAlg()
      # req_body = {"name": name}
      r = requests.post(url=kms_api_base+"/get/key/cpabe-sk", headers=hed, **kw_auth) # , json=req_body
      raw_key = r.content
      key = bsw07.deserialize_charm_obj(raw_key)
      return key
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None


def post_enc_data(base_url,data, auth=None, debug=False):  
   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      if type(data["index"]) != list or len(data)<=0:
         return False

      ser_data = pickle.dumps(data)
      r = requests.post(url=base_url+"/add/enc-data",
                          data=ser_data,
                          headers={'Content-Type': 'application/octet-stream'},
                          **kw_auth)
      
      if r.status_code >= 300:
         return False
      return True

   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return False

def query_enc_data(base_url, enc_val, query_type="search",
                  enc_left_epoch=None, enc_right_epoch=None,
                  left_inclusive=None, right_inclusive=None,
                  auth=None, debug=False):
   try:
      if type(enc_val) != bytes:
         return None
      if type(enc_left_epoch) != bytes and enc_left_epoch != None:
         return None
      if type(enc_right_epoch) != bytes and enc_right_epoch != None:
         return None
      if type(left_inclusive) != bool and left_inclusive != None:
         return None
      if type(right_inclusive) != bool and right_inclusive != None:
         return None

      if not (query_type == "search" or query_type == "count"):
         return None

      kw_auth = {}
      if auth != None:
         kw_auth["auth"] = auth

      data = {"query_type": query_type, "index": enc_val}
      if enc_left_epoch:
         data["time_left"] = enc_left_epoch
      if enc_right_epoch:
         data["time_right"] = enc_right_epoch

      if left_inclusive:
         data["left_inclusive"] = left_inclusive
      if right_inclusive:
         data["right_inclusive"] = right_inclusive

      ser_data = pickle.dumps(data)
      # print(ser_data)
      r = requests.post(url=base_url+"/query",
                          data=ser_data,
                          headers={'Content-Type': 'application/octet-stream'},
                          **kw_auth)
      
      if r.status_code >= 300:
         if debug:
            print("status code:", r.status_code)
         return None
      return r.content

   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None

   
def list_all_attributes(kms_api_base,token, auth=None):
   if type(token) != str:
      return None
   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      r = requests.get(url=kms_api_base+"/get/attributes", headers=hed, **kw_auth)
      if r.status_code >= 300:
         return None
      return r.content

   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def get_ore_params(kms_api_base,token, auth=None):
   if type(token) != str:
      return None
   hed = {'X-Authorization': 'Bearer ' + token}

   kw_auth = {}
   if auth != None:
      kw_auth["auth"] = auth

   try:
      r = requests.get(url=kms_api_base+"/get/range/ore", headers=hed, **kw_auth)
      if r.status_code >= 300:
         return None
      return r.json()

   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      if debug:
         traceback.print_exc()
      return None



def test_auth(api_base, auth):
   r = requests.get(url=api_base+"/", auth=auth)
   if r.status_code >= 300:
      return False
   return True


def test_token(kms_api_base, token, auth=None):
   hed = {'X-Authorization': 'Bearer ' + token}
   auth_header = {}
   if auth:
      auth_header = {"auth": auth}
      
   r = requests.get(url=kms_api_base+"/user/me", headers=hed, **auth_header)
   if r.status_code >= 300:
      return False
   return True