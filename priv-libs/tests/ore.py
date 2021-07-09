import sys
sys.path.append("/priv-libs/libs")

from ORE import *

a = OREcipher()
b = OREcipher(a.export_key(), a.export_params())


one_a = a.encrypt(10)
two_a = a.encrypt(1337)
three_a = a.encrypt(99999)
one_b = b.encrypt(10)
two_b = b.encrypt(1337)
three_b = b.encrypt(99999)

# print(one_a)
# print(two_a)
# print(three_a)
# print(one_b)
# print(two_b)
# print(three_b)

assert one_a < two_a < three_a
assert one_b < two_b < three_b
assert one_a == one_b
assert two_a == two_b
assert three_a == three_b

assert a.encrypt(9) < one_a < a.encrypt(11)
assert a.encrypt(1336) < two_a < a.encrypt(1338)
assert a.encrypt(99998) < three_a < a.encrypt(100000)


assert b.encrypt(9) < one_b < b.encrypt(11)
assert b.encrypt(1336) < two_b < b.encrypt(1338)
assert b.encrypt(99998) < three_b < b.encrypt(100000)

print("all tests pass")