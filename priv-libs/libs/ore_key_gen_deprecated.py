#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")

import pickle
import random
import tempfile
import traceback

from ORE import *




def exp_k_test_helper(secret_key:ORESecretKey=ORESecretKey.from_random()):

    vals = [
        (chr(c), OREComparable.from_int(c - 96, secret_key))
        for c in range(ord("a"), ord("z") + 1)
    ]


    random.shuffle(vals)
    # print(vals)

    vals_sort_enc = sorted(vals, key=lambda tupl: tupl[1])
    vals_sort_char = sorted( vals, key=lambda tupl: tupl[0])
    assert  vals_sort_enc == vals_sort_char, "encrypted and raw values where not sorted correctly"
    return (vals, vals_sort_enc,vals_sort_char )


def pickle_exp_imp(data):
    p = pickle.dumps(data)
    return pickle.loads(p)



def export_key_test(secret_key:ORESecretKey=ORESecretKey.from_random()):

    # print("\n\nTesting Export/import key")
    # print("key:", secret_key)
    # print([secret_key.key.keybuf[i] for i in range(32)])

    # print()
    # print("testing key before exporting it.")
    vals1 = exp_k_test_helper(secret_key)
    # print("passed")
    exported_key = secret_key.export()

    exp_key2 = pickle_exp_imp(exported_key)


    s2 = ORESecretKey.from_raw_bytes(exp_key2)
    # print("imported key:",s2)
    # print([s2.key.keybuf[i] for i in range(32)])
    # print()
    # print("testing imported key")
    vals2 = exp_k_test_helper(s2)
    # print("passed\n")


    # print(vals1)
    # print(vals2)
    # print("comparing encrypted values")
    # assert vals1 == vals2, "encrypted vals are not the same"
    # prnit("passed")

def export_cipher_test(secret_key:ORESecretKey=ORESecretKey.from_random()):
    # print("\n\nTesting Export/import ciphertext")

    # print("key: ", secret_key)


    # print("creating comparable objects")
    cipher_one = OREComparable.from_int(1,secret_key)
    cipher_five = OREComparable.from_int(5,secret_key)
    cipher_ten = OREComparable.from_int(10,secret_key)

    # print("passed\nexporting and importing cipher objects")
    exp1 = pickle_exp_imp(cipher_one.get_cipher_obj().export())
    exp5 = pickle_exp_imp(cipher_five.get_cipher_obj().export())
    exp10 = pickle_exp_imp(cipher_ten.get_cipher_obj().export())

    # print("passed\ncreating cipher objects")
    exp1 = ORECiphertext.from_raw_bytes(exp1)
    exp5 = ORECiphertext.from_raw_bytes(exp5)
    exp10 = ORECiphertext.from_raw_bytes(exp10)

    # print("passed\nrecreating comparable from imported ciphertexyt objects")
    c_1_imp = OREComparable(exp1)
    c_5_imp = OREComparable(exp5)
    c_10_imp = OREComparable(exp10)

    # print("passed\ndoing comparison tests")

    assert cipher_one == c_1_imp
    assert cipher_five == c_5_imp
    assert cipher_ten == c_10_imp

    assert cipher_one < c_5_imp
    assert cipher_one < c_10_imp

    assert cipher_five > c_1_imp
    assert cipher_five < c_10_imp

    assert cipher_ten > c_1_imp
    assert cipher_ten > c_5_imp

    assert c_1_imp < c_5_imp
    assert c_1_imp < c_10_imp

    assert c_5_imp > c_1_imp
    assert c_5_imp < c_10_imp

    assert c_10_imp > c_1_imp
    assert c_10_imp > c_5_imp





def gen_ore_key_rand():
    while True:
        secret_key_candidate = ORESecretKey.from_random()

        try:
            exp_k_test_helper(secret_key_candidate)
            export_key_test(secret_key_candidate)
            export_cipher_test(secret_key_candidate)

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            # print("trying new key")
            # traceback.print_exc()
            continue

        return secret_key_candidate.export()



if __name__ == '__main__':
    print("New rand key:")
    print(gen_ore_key_rand())