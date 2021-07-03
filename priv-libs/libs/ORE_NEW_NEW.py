import hashlib
import random, os
from string import ascii_uppercase, digits
LEN = 16





# def int_comp(u, v):
#     if u == v:
#         return 0
#     elif u > v:
#         return 1
#     else:
#         return -1


# from pyope.ope import OPE
# random_key = OPE.generate_key()
# assert cipher.encrypt(1000) < cipher.encrypt(2000) < cipher.encrypt(3000)
# assert cipher.decrypt(cipher.encrypt(1337)) == 1337



# cnt = 0
# tests = 100
# for i in range(tests):
#     random_key = OPE.generate_key()
#     cipher = OPE(random_key)

#     num1 = random.randrange(1, 2**64)
#     num2 = random.randrange(1, 2**64)

#     a = ore_enc(int2str_bin(10), passwd)
#     b = ore_enc(int2str_bin(12), passwd)
#     print("a", a)
#     print("b", b)
#     if ore_comp(a, b) == int_comp(num1, num2):
#         cnt += 1
# print(f"Succeded in: {cnt} out of {tests} tests.")


from pyope.ope import OPE
random_key = OPE.generate_key()

cipher = OPE(random_key)

a = cipher.encrypt(1000)
b = cipher.encrypt(2000)
c = cipher.encrypt(3000)
print(a)
print(b)
print(c)

print(cipher.decrypt(cipher.encrypt(1337)))