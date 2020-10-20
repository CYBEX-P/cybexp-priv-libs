import ctypes

orelib = ctypes.cdll.LoadLibrary("./ore.so")


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


class PRFKey(ctypes.Structure):
    _fields_ = [("keybuf", ctypes.c_byte * 32)]


class ORESecretKey(ctypes.Structure):
    _fields_ = [("initialized", ctypes.c_bool), ("key", PRFKey), ("params", OREParams)]


class ORECiphertext(ctypes.Structure):
    _fields_ = [
        ("initialized", ctypes.c_bool),
        ("buf", ctypes.c_char_p),
        ("params", OREParams),
    ]


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
        if code > 0 and code < len(cls.error_codes):
            msg = cls.error_codes[code]
        else:
            msg = f"UNKNOWN ERR (={code})"
        return ORELibError(msg)


_params: OREParams = None


def default_ore_params():
    global _params

    if not _params:
        _params = OREParams()

        orelib.init_ore_params(
            ctypes.byref(_params), ctypes.c_uint32(31), ctypes.c_uint32(31)
        )

    return _params


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


def test():
    secret_key = ORESecretKey()

    orelib.ore_setup(ctypes.byref(secret_key), ctypes.byref(default_ore_params()))

    vals = [
        (chr(c), OREComparable.from_int(c - 96, secret_key))
        for c in range(ord("a"), ord("z") + 1)
    ]

    import random

    random.shuffle(vals)
    # print(vals)

    assert sorted(vals, key=lambda tupl: tupl[1]) == sorted(
        vals, key=lambda tupl: tupl[0]
    )

    print("Passed!")


if __name__ == "__main__":
    test()