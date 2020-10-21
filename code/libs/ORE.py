import ctypes
import struct
import traceback 

orelib = ctypes.cdll.LoadLibrary("../fastore-lib/ore.so")


class PrintableCtypesStructure(ctypes.Structure):
    def __str__(self):
        return "{}: {{{}}}".format(
            self.__class__.__name__,
            ", ".join(
                [
                    "{}: {}".format(field[0], getattr(self, field[0]))
                    for field in self._fields_
                ]
            ),
        )


# Enable pretty-printing of ctypes structs
ctypes.Structure = PrintableCtypesStructure




class OREParams(ctypes.Structure):
    _fields_ = [
        ("initialized", ctypes.c_bool),
        ("nbits", ctypes.c_uint32),
        ("out_blk_len", ctypes.c_uint32),
    ]

    # net(big endian), bool, uint32, uint32
    struct_format = "!?II"
    struct_my_size = 9 #bytes

    def export(self):
        return struct.pack(self.struct_format,self.initialized, self.nbits, self.out_blk_len)

    @classmethod
    def unpack_vals(cls, raw_bytes):
        try:
            if len(raw_bytes) != cls.struct_my_size:
                return None
            vals = struct.unpack(cls.struct_format,raw_bytes)
            return vals
        except:
            print("error")
            return None

    @classmethod
    def from_raw_bytes(cls, raw_bytes):
        vals = cls.unpack_vals(raw_bytes)
        return cls(*vals)

    @classmethod
    def from_new(cls):
        _params = cls()

        orelib.init_ore_params(
            ctypes.byref(_params), ctypes.c_uint32(31), ctypes.c_uint32(31)
        )

        return _params

_params: OREParams = None
def default_ore_params() -> OREParams:
    global _params

    if not _params:
        _params = OREParams()

        orelib.init_ore_params(
            ctypes.byref(_params), ctypes.c_uint32(31), ctypes.c_uint32(31)
        )

    return _params


class PRFKey(ctypes.Structure):
    _fields_ = [("keybuf", ctypes.c_byte * 32)]
   
    # net(big endian), byte*32(treated as int by ctype and python and struct)
    struct_format = "!"+ "b"*32 
    struct_my_size = 32 #bytes
    def export(self):
        return struct.pack(self.struct_format,*[v for v in self.keybuf])

    @classmethod
    def unpack_vals(cls, raw_bytes):
        try:
            if len(raw_bytes) != cls.struct_my_size:
                return None
            vals = struct.unpack(cls.struct_format,raw_bytes)
            byte32Array = ctypes.c_byte * 32
            # conversion to ctype array, else __init__ fails
            return (byte32Array(*vals),) # in typle for consystemcy with other functions
            
        except:
            print("error")
            return None

    @classmethod
    def from_raw_bytes(cls, raw_bytes):
        vals = cls.unpack_vals(raw_bytes)
        return cls(*vals)

class ORESecretKey(ctypes.Structure):
    _fields_ = [("initialized", ctypes.c_bool), ("key", PRFKey), ("params", OREParams)]

    # net(big endian), bool, +key, +params 
    struct_format = "!?"
    struct_my_size = 1 #byte
    struct_key_size = 32 #bytes
    struct_params_size = 9 #bytes
    struct_total_size = struct_my_size+struct_key_size+struct_params_size

    def export(self): 
        me_export = struct.pack(self.struct_format,self.initialized)
        key_export = self.key.export()
        params_export = self.params.export()

        return me_export+key_export+params_export    

    @classmethod
    def unpack_vals(cls, raw_bytes):
        try:
            if len(raw_bytes) != cls.struct_total_size:
                return None
            raw_me = raw_bytes[:cls.struct_my_size]
            raw_key = raw_bytes[cls.struct_my_size:cls.struct_my_size+cls.struct_key_size]
            raw_params = raw_bytes[cls.struct_my_size+cls.struct_key_size:]
            me = struct.unpack(cls.struct_format,raw_me)
            key = PRFKey.unpack_vals(raw_key)
            params = OREParams.unpack_vals(raw_params)

            return (me,key,params)
        except:
            traceback.print_exc()
            print("error")
            return None

    @classmethod
    def from_raw_bytes(cls, raw_bytes):
        vals = cls.unpack_vals(raw_bytes)
        key_obj = PRFKey(*vals[1])
        param_obj = OREParams(*vals[2])

        return cls(*vals[0], key_obj, param_obj)

    @classmethod
    def from_random(cls, params:OREParams=OREParams.from_new()):
        secret_key = cls()
        # generate rand key
        orelib.ore_setup(ctypes.byref(secret_key), ctypes.byref(params))
        return secret_key

class ORECiphertext(ctypes.Structure):
    _fields_ = [
        ("initialized", ctypes.c_bool),
        ("buf", ctypes.c_char_p),
        ("params", OREParams),
    ]

    # # netowrk(big-endian), bool, + char*ore_ciphertext_size(buf), +params
    # struct_format = "!?"
    # struct_params_size = 9 #bytes

    # @classmethod
    # def export(cls):
    #     buf_size = ore_ciphertext_size(self.params)

    #     raw_me = struct.pack(cls.struct_format, self.initialized)
    #     raw_params = self.params.export()
    #     raw_buf = struct.pack('!'+'B'*buf_size,*[self.buf[i] for i in range(buf_size)])

    #     return raw_me + raw_params + raw_buf





class ORELibError(Exception):
    error_codes = [
        "ERROR_NONE",
        "ERROR_RANDOMNESS",
        "ERROR_SRCLEN_INVALID",
        "ERROR_DSTLEN_INVALID",
        "ERROR_PRF_KEYLEN_INVALID",
        "ERROR_PRP_BITLEN_INVALID",
        "ERROR_NULL_POINTER",
        "ERROR_MEMORY_ALLOCATION",
        "ERROR_PARAMS_MISMATCH",
        "ERROR_PARAMS_INVALID",
        "ERROR_SK_NOT_INITIALIZED",
        "ERROR_CTXT_NOT_INITIALIZED",
        "ERROR_UNSUPPORTED_OPERATION",
    ]

    @classmethod
    def fromcode(cls, code: int) -> "ORELibError":
        if 0 < code < len(cls.error_codes):
            msg = cls.error_codes[code]
        else:
            msg = f"UNKNOWN ERR (={code})"
        return ORELibError(msg)





class OREComparable:
    def __init__(self, ciphertext_obj: ORECiphertext):
        ct_is_ready = ciphertext_obj.params.initialized and ciphertext_obj.initialized
        # TODO: This doesn't verify that the CT obj is actually a CT
        assert ct_is_ready, "Comparable must use an initialized ct."
        self.ciphertext_obj = ciphertext_obj

    @classmethod
    def from_int(
        cls,
        val: int,
        secret_key: ORESecretKey,
        params: OREParams = default_ore_params(),
    ) -> "OREComparable":
        ciphertext_obj = ORECiphertext()

        retcode = orelib.init_ore_ciphertext(
            ctypes.byref(ciphertext_obj), ctypes.byref(params)
        )

        if retcode:
            raise ORELibError.fromcode(retcode)

        retcode = orelib.ore_encrypt_ui(
            ctypes.byref(ciphertext_obj),
            ctypes.byref(secret_key),
            ctypes.c_uint32(val),
        )

        if retcode:
            raise ORELibError.fromcode(retcode)

        return OREComparable(ciphertext_obj)

    def __lt__(self, other):
        return self._cmp(other) == -1

    def __eq__(self, other):
        return self._cmp(other) == 0

    def _cmp(self, other: "OREComparable") -> int:
        assert type(other) == OREComparable, f"{other} is not a ciphertext"
        res = ctypes.c_int()

        retcode = orelib.ore_compare(
            ctypes.byref(res),
            ctypes.byref(self.ciphertext_obj),
            ctypes.byref(other.ciphertext_obj),
        )

        if retcode:
            raise ORELibError.fromcode(retcode)

        return res.value




# def local_test():
#     secret_key = ORESecretKey()
#     print(secret_key)
    
#     orelib.ore_setup(ctypes.byref(secret_key), ctypes.byref(default_ore_params()))

#     vals = [
#         (chr(c), OREComparable.from_int(c - 96, secret_key))
#         for c in range(ord("a"), ord("z") + 1)
#     ]

#     import random

#     random.shuffle(vals)
#     # print(vals)

#     assert sorted(vals, key=lambda tupl: tupl[1]) == sorted(
#         vals, key=lambda tupl: tupl[0]
#     )

#     print("Local Test Passed!")
#     e = secret_key.export()
#     print()
#     print(e)
#     print()
#     s2 = ORESecretKey.from_raw_bytes(e)
#     print(s2)


def exp_k_test_helper(secret_key:ORESecretKey=ORESecretKey.from_random()):

    vals = [
        (chr(c), OREComparable.from_int(c - 96, secret_key))
        for c in range(ord("a"), ord("z") + 1)
    ]

    import random

    random.shuffle(vals)
    # print(vals)

    vals_sort_enc = sorted(vals, key=lambda tupl: tupl[1])
    vals_sort_char = sorted( vals, key=lambda tupl: tupl[0])
    assert  vals_sort_enc == vals_sort_char, "encrypted and raw values where not sorted correctly"
    return (vals, vals_sort_enc,vals_sort_char )


def export_key_test():
    import pickle

    secret_key = ORESecretKey.from_random()

    print("rand key: ", secret_key)

    print("testing key before exporting it.")
    vals1 = exp_k_test_helper(secret_key)
    print("passed")
    exported_key = secret_key.export()

    pickle.dump(exported_key,open( "secretkey.bin", "wb" ))
    exp_key2 = pickle.load(open( "secretkey.bin", "rb" ))

    s2 = ORESecretKey.from_raw_bytes(exp_key2)
    print("imported key: ",s2)
    print()
    print("testing imported key")
    vals2 = exp_k_test_helper(s2)
    print("passed\n")


    # print(vals1)
    # print(vals2)
    # print("comparing encrypted values")
    # assert vals1 == vals2, "encrypted vals are not the same"
    # prnit("passed")


if __name__ == "__main__":
    exp_k_test_helper()
    export_key_test()