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
from unittest import TestCase
from urtypes.crypto import HDKey, CoinInfo, Keypath, PathComponent


class HDKeyTestCase(TestCase):
    def table(self):
        return [
            {
                "test": "Example/Test Vector 1 (master key)",
                "item": HDKey(
                    {
                        "master": True,
                        "key": binascii.unhexlify(
                            "00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
                        ),
                        "chain_code": binascii.unhexlify(
                            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
                        ),
                    }
                ),
                "cbor": binascii.unhexlify(
                    "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35045820873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
                ),
            },
            {
                "test": "Example/Test Vector 2 (bitcoin testnet public key with derivation path m/44'/1'/1'/0/1)",
                "item": HDKey(
                    {
                        "key": binascii.unhexlify(
                            "026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6"
                        ),
                        "chain_code": binascii.unhexlify(
                            "ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85"
                        ),
                        "use_info": CoinInfo(None, 1),
                        "origin": Keypath(
                            [
                                PathComponent(44, True),
                                PathComponent(1, True),
                                PathComponent(1, True),
                                PathComponent(0, False),
                                PathComponent(1, False),
                            ],
                            None,
                            None,
                        ),
                        "parent_fingerprint": binascii.unhexlify("e9181cf3"),
                    }
                ),
                "cbor": binascii.unhexlify(
                    "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c8505d90131a1020106d90130a1018a182cf501f501f500f401f4081ae9181cf3"
                ),
            },
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(HDKey.from_cbor(row["cbor"]), row["item"])

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(row["item"].to_cbor(), row["cbor"])
