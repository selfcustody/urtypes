# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import binascii
from ..registry import RegistryType, RegistryItem

CRYPTO_HDKEY = RegistryType("crypto-hdkey", 303)

_ZERO4 = (0).to_bytes(4, "big")
_ZERO32 = (0).to_bytes(32, "big")

_XPRV = binascii.unhexlify("0488ADE4")
_TPRV = binascii.unhexlify("04358394")
_XPUB = binascii.unhexlify("0488B21E")
_TPUB = binascii.unhexlify("043587CF")


class HDKey(RegistryItem):
    def __init__(self, props):
        self.master = None
        self.key = None
        self.chain_code = None
        self.private_key = None
        self.use_info = None
        self.origin = None
        self.children = None
        self.parent_fingerprint = None
        self.name = None
        self.note = None
        if "master" in props and props["master"]:
            self.setup_master_key(props)
        else:
            self.setup_derive_key(props)

    @classmethod
    def registry_type(cls):
        return CRYPTO_HDKEY

    def setup_master_key(self, props):
        self.master = True
        self.key = props["key"] if "key" in props else None
        self.chain_code = props["chain_code"] if "chain_code" in props else None

    def setup_derive_key(self, props):
        self.master = False
        get = props.get
        self.key = get("key")
        self.chain_code = get("chain_code")
        self.private_key = get("private_key")
        self.use_info = get("use_info")
        self.origin = get("origin")
        self.children = get("children")
        self.parent_fingerprint = get("parent_fingerprint")
        self.name = get("name")
        self.note = get("note")

    def bip32_key(self, include_derivation_path=False):
        parent_fp = self.parent_fingerprint or _ZERO4
        chain = self.chain_code or _ZERO32
        key = self.key
        if len(key) == 32:
            key = b"\x00" + key

        depth = 0
        index = 0
        source_is_parent = False

        if self.master:
            version = (
                _XPRV if not self.use_info or self.use_info.network == 0 else _TPRV
            )
        else:
            if self.private_key:
                version = (
                    _XPRV if not self.use_info or self.use_info.network == 0 else _TPRV
                )
            else:
                version = (
                    _XPUB if not self.use_info or self.use_info.network == 0 else _TPUB
                )

            origin = self.origin
            if origin:
                depth = (
                    origin.depth if origin.depth is not None else len(origin.components)
                )
                paths = origin.components
                if paths:
                    last = paths[-1]
                    index = last.index + (0x80000000 if last.hardened else 0)
                    if (
                        self.parent_fingerprint is None
                        and origin.source_fingerprint
                        and len(paths) == 1
                    ):
                        parent_fp = origin.source_fingerprint
                        source_is_parent = True

        payload = (
            version
            + depth.to_bytes(1, "big")
            + parent_fp
            + index.to_bytes(4, "big")
            + chain
            + key
        )

        encoded = encode_check(payload)  # key

        if not include_derivation_path:
            return encoded

        deriv = ""
        if (
            self.origin
            and self.origin.path()
            and self.origin.source_fingerprint
            and not source_is_parent
        ):
            deriv = "[%s/%s]" % (
                binascii.hexlify(self.origin.source_fingerprint).decode("utf-8"),
                self.origin.path(),
            )

        child = ""
        if self.children and self.children.path():
            child = "/" + self.children.path()

        return deriv + encoded + child

    def descriptor_key(self):
        return self.bip32_key(True)

    def to_data_item(self):
        _map = {}
        if self.master:
            _map[1] = True
            _map[3] = self.key
            if self.chain_code is not None:
                _map[4] = self.chain_code
            return _map

        from ..cbor.data import DataItem

        if self.private_key is not None:
            _map[2] = self.private_key
        _map[3] = self.key

        if self.chain_code is not None:
            _map[4] = self.chain_code
        if self.use_info is not None:
            _map[5] = DataItem(
                self.use_info.registry_type().tag, self.use_info.to_data_item()
            )
        if self.origin is not None:
            _map[6] = DataItem(
                self.origin.registry_type().tag, self.origin.to_data_item()
            )
        if self.children is not None:
            _map[7] = DataItem(
                self.children.registry_type().tag, self.children.to_data_item()
            )
        if self.parent_fingerprint is not None:
            _map[8] = int.from_bytes(self.parent_fingerprint, "big")
        if self.name is not None:
            _map[9] = self.name
        if self.note is not None:
            _map[10] = self.note

        return _map

    @classmethod
    def from_data_item(cls, item):
        from .coin_info import CoinInfo
        from .keypath import Keypath

        m = cls.mapping(item)
        get = m.get

        return cls(
            {
                "master": bool(get(1)),
                "private_key": get(2),
                "key": get(3),
                "chain_code": get(4),
                "use_info": CoinInfo.from_data_item(get(5)) if 5 in m else None,
                "origin": Keypath.from_data_item(get(6)) if 6 in m else None,
                "children": Keypath.from_data_item(get(7)) if 7 in m else None,
                "parent_fingerprint": get(8).to_bytes(4, "big") if 8 in m else None,
                "name": get(9),
                "note": get(10),
            }
        )


def double_sha256(msg):
    """sha256(sha256(msg)) -> bytes"""
    import hashlib

    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def encode(b):
    """Encode bytes to a base58-encoded string"""

    B58_DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    n = int.from_bytes(b, "big")
    res = []
    while n:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res.reverse()

    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break

    return B58_DIGITS[0] * pad + "".join(res)


def encode_check(b):
    """Encode bytes to a base58-encoded string with a checksum"""
    return encode(b + double_sha256(b)[:4])
