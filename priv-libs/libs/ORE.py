#!/usr/bin/env python3 

import ctypes
import struct
import traceback 

orelib = ctypes.cdll.LoadLibrary("/priv-libs/fastore-lib/ore.so")


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


    def buff_size(self):
        return (self.nbits * self.out_blk_len + 7) // 8;
    
    @classmethod
    def buff_size_from_unpacked_vals(cls,tup):
        return (tup[1] * tup[2] + 7) // 8;

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

    # netowrk(big-endian), bool, + char*ore_ciphertext_size(buf), +params
    struct_format = "!?"
    struct_params_size = 9 #bytes
    struct_total_min = 10 # bytes

    def export(self):
        # params = OREParams(self.params)
        params = self.params
        buf_size = params.buff_size()
        print(buf_size)
        # print(params.initialized,params.nbits,params.out_blk_len)



        raw_me = struct.pack(self.struct_format, self.initialized)
        raw_params = params.export()
        # print("raw", raw_params)
        # print(type(self.buf))
        raw_buf = struct.pack('!'+'B'*buf_size,*[self.buf[i] for i in range(buf_size)])

        return raw_me + raw_params + raw_buf



    @classmethod
    def unpack_vals(cls, raw_bytes):
        try:
            if len(raw_bytes) < cls.struct_total_min:
                return None
            raw_me = raw_bytes[:1]
            raw_params = raw_bytes[1:10]
            raw_buff = raw_bytes[10:]

            me = struct.unpack(cls.struct_format,raw_me)
            params = OREParams.unpack_vals(raw_params)
            # print(params)
            buf_size = OREParams.buff_size_from_unpacked_vals(params)
            # print(buf_size)
            if buf_size != len(raw_buff):
                return None

            buff = struct.unpack('!'+'B'*buf_size,raw_buff)

            bytes_buff = bytes(buff)

            if buf_size == 0:
                raise
            buff_p = ctypes.c_char_p(bytes_buff)

            return (me,buff_p,params)
        except:
            traceback.print_exc()
            print("error")
            return None


    @classmethod
    def from_raw_bytes(cls, raw_bytes):
        vals = cls.unpack_vals(raw_bytes)
        param_obj = OREParams(*vals[2])

        return cls(vals[0],vals[1], param_obj)




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
        # print(ciphertext_obj)
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
        comp = self._cmp(other)
        print(comp)
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

    def get_cipher_obj(self):
        return self.ciphertext_obj




