

from pyope.ope import OPE

def gen_ore_key_rand(length=256):
   return OPE.generate_key(length)
