import hashlib
import random, os
from string import ascii_uppercase, digits
LEN = 16


def rnd_word(n):
    return ''.join(random.choice(ascii_uppercase + digits) for _ in range(n))
    # return os.urandom(n) 

def prf(msg, k):
    pad = "0" * (LEN - len(msg))
    return int(hashlib.sha224((str(msg) + pad + str(k)).encode()).hexdigest(), 16)


def ore_enc(m, k):
    tmp_m = ""
    tmpres = ""
    for i in m:
        tmp_m += i
        tmpres += str((prf(tmp_m[:-1], k) + int(tmp_m[-1])) % 3)
    return tmpres


def ore_comp(u, v):
    if u == v:
        return 0
    L = len(u)
    cnt = 0
    while u[cnt] == v[cnt]:
        cnt += 1
    if (int(u[cnt]) + 1) % 3 == int(v[cnt]):
        return -1
    else:
        return 1


def int_comp(u, v):
    if u == v:
        return 0
    elif u > v:
        return 1
    else:
        return -1


def int2str_bin(numb):
    return bin(numb)[2:]

cnt = 0
tests = 100
for i in range(tests):
    passwd = rnd_word(10)
    # print(passwd)
    num1 = random.randrange(2**63, 2**64)
    num2 = random.randrange(2**63, 2**64)

    a = ore_enc(int2str_bin(10), passwd)
    b = ore_enc(int2str_bin(12), passwd)
    print("a", a)
    print("b", b)
    if ore_comp(a, b) == int_comp(num1, num2):
        cnt += 1
print(f"Succeded in: {cnt} out of {tests} tests.")
