# import sys
# sys.path.append("/home/nacho/Projects/cybexp-privacy/charm-build/charm")

import pickle
from typing import Any, Dict, List, Union
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc

# from charm.engine.util import objectToBytes,bytesToObject


# ref 
# https://share.cocalc.com/share/f61d4c2e7d3a2ed92d6304be6bec5b3cacda5299/tmp/Charm-Crypto-0.43/charm/adapters/abenc_adapt_hybrid.py?viewer=share

def is_pickle(obj):
    try:
        pickle.loads(obj)

    except _pickle.UnpicklingError:
        return False
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    return True

class CPABEAlg:
    """ Wraps CP-ABE functionality from charm-crypto. """

    def __init__(self, group_name: str = "SS512"):
        self.group = PairingGroup(group_name)
        self.alg = CPabe_BSW07(self.group)
        self.hyb_abe = HybridABEnc(self.alg, self.group)

    def cpabe_encrypt_raw(self, pk, plaintext: bytes, access_policy: str) -> bytes:
        return self.hyb_abe.encrypt(pk, plaintext, access_policy)


    def cpabe_decrypt_raw(self, pk, sk, ciphertext: bytes) -> bytes:
        return self.hyb_abe.decrypt(pk, sk, ciphertext)

    def cpabe_encrypt_serialize(self, pk, plaintext: bytes, access_policy: str) -> bytes:
        ciphertext = self.cpabe_encrypt_raw(pk, plaintext, access_policy)
        return self.serialize_charm_obj(ciphertext)

    def cpabe_decrypt_deserialize(self, pk, sk, ciphertext: bytes) -> bytes:
        ciphertext2 = self.deserialize_charm_obj(ciphertext)
        return self.cpabe_decrypt_raw(pk, sk, ciphertext2)

    def _serialize_charm_obj(self, charm_obj: Union[Dict, List, Any]) -> bytes:
        if isinstance(charm_obj, dict):
            return {k: self._serialize_charm_obj(v) for (k, v) in charm_obj.items()}
        elif isinstance(charm_obj, list):
            return [self._serialize_charm_obj(x) for x in charm_obj]
        elif "Element" in type(charm_obj).__name__:
            return self.group.serialize(charm_obj)

        # Don't serialize non-CHARM fields
        return charm_obj

    def _deserialize_charm_obj(self, charm_obj: Union[Dict, List, Any]):
        # print("->>>>>>>>>", charm_obj)
        if isinstance(charm_obj, dict):
            return {k: self._deserialize_charm_obj(v) for (k, v) in charm_obj.items()}
        elif isinstance(charm_obj, list):
            return [self._deserialize_charm_obj(x) for x in charm_obj]
        elif isinstance(charm_obj, bytes):# and not is_pickle(charm_obj):
            return self.group.deserialize(charm_obj)

        return charm_obj



    def serialize_charm_obj(self, charm_obj):
        pkl = self._serialize_charm_obj(charm_obj)
        # print("pikling:", pkl)
        return pickle.dumps(pkl)

    def deserialize_charm_obj(self, charm_obj):
        # return pickle.loads(self._deserialize_charm_obj(charm_obj))
        raw = pickle.loads(charm_obj)
        return self._deserialize_charm_obj(raw)