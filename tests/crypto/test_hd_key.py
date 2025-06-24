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
                "descriptor_key": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
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
                "descriptor_key": "tpubDHW3GtnVrTatx38EcygoSf9UhUd9Dx1rht7FAL8unrMo8r2NWhJuYNqDFS7cZFVbDaxJkV94MLZAr86XFPsAPYcoHWJ7sWYsrmHDw5sKQ2K",
            },
        ]

    def descriptor_table(self):
        return [
            {
                "test": "master key",
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
                "descriptor_key": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            },
            {
                "test": "xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0'",
                "item": HDKey(
                    {
                        "key": binascii.unhexlify(
                            "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
                        ),
                        "chain_code": binascii.unhexlify(
                            "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
                        ),
                        "origin": Keypath(
                            [
                                PathComponent(44, True),
                                PathComponent(0, True),
                                PathComponent(0, True),
                            ],
                            binascii.unhexlify("d34db33f"),
                            None,
                        ),
                        "parent_fingerprint": binascii.unhexlify("78412e3a"),
                    }
                ),
                "descriptor_key": "[d34db33f/44'/0'/0']xpub6CY2xt3mvQejPFUw26CychtL4GMq1yp41aMW2U27mvThqefpZYwXpGscV26JuVj13Fpg4kgSENheUSbTqm5f8z25zrhXpPVss5zWeMGnAKR",
            },
            {
                "test": "xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0', with child derivation",
                "item": HDKey(
                    {
                        "key": binascii.unhexlify(
                            "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
                        ),
                        "chain_code": binascii.unhexlify(
                            "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
                        ),
                        "origin": Keypath(
                            [
                                PathComponent(44, True),
                                PathComponent(0, True),
                                PathComponent(0, True),
                            ],
                            binascii.unhexlify("d34db33f"),
                            None,
                        ),
                        "children": Keypath(
                            [PathComponent(1, False), PathComponent(None, False)],
                            None,
                            None,
                        ),
                        "parent_fingerprint": binascii.unhexlify("78412e3a"),
                    }
                ),
                "descriptor_key": "[d34db33f/44'/0'/0']xpub6CY2xt3mvQejPFUw26CychtL4GMq1yp41aMW2U27mvThqefpZYwXpGscV26JuVj13Fpg4kgSENheUSbTqm5f8z25zrhXpPVss5zWeMGnAKR/1/*",
            },
            {
                "test": "m/84'/1'/0'",
                "item": HDKey(
                    {
                        "key": binascii.unhexlify(
                            "0204ab245e5417bcdc52e2a6b92fafa2c8ce54ba97d4b1216f074915870000f946"
                        ),
                        "chain_code": binascii.unhexlify(
                            "9c6bf9263cab713ed098edcd147c651dfc924d953c11ad095a70f9bd31de1d8c"
                        ),
                        "use_info": CoinInfo(None, 1),
                        "origin": Keypath(
                            [
                                PathComponent(84, True),
                                PathComponent(1, True),
                                PathComponent(0, True),
                            ],
                            binascii.unhexlify("55f8fc5d"),
                            3,
                        ),
                        "parent_fingerprint": binascii.unhexlify("1b01c99c"),
                    }
                ),
                "descriptor_key": "[55f8fc5d/84'/1'/0']tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s",
            },
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(HDKey.from_cbor(row["cbor"]), row["item"])

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(row["item"].to_cbor(), row["cbor"])

    def test_descriptor_key(self):
        for row in self.descriptor_table():
            self.assertEqual(row["item"].descriptor_key(), row["descriptor_key"])

    def test_from_descriptor_key(self):
        for row in self.descriptor_table():
            self.assertEqual(
                HDKey.from_descriptor_key(row["descriptor_key"]).descriptor_key(),
                row["descriptor_key"],
            )
            self.assertEqual(
                HDKey.from_descriptor_key(row["descriptor_key"]).descriptor_key(),
                row["item"].descriptor_key(),
            )
