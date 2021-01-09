#!/usr/bin/env python3

import sys
# sys.path.append("/priv-libs/libs")

import yaml
import jsonlines



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