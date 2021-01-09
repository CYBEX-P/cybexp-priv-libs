#!/usr/bin/env python3

import sys
# sys.path.append("/priv-libs/libs")

from pprint import pprint
import traceback
import pymongo 



def create_index(col, name):
   col.create_index(name)

def get_collection(uri, db_name, col_name, connect=False):
   myclient = pymongo.MongoClient(uri,connect=connect)
   mydb = myclient[db_name]
   mycol = mydb[col_name]
   return mycol