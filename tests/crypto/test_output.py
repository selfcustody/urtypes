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
from urtypes.crypto import (
    Keypath,
    PathComponent,
    MultiKey,
    ECKey,
    HDKey,
    Output,
    SCRIPT_EXPRESSION_TAG_MAP,
)


class OutputTestCase(TestCase):
    def table(self):
        return [
            {
                "test": "Example/Test Vector 1 (P2PKH output with the specified public key)",
                "item": Output(
                    [SCRIPT_EXPRESSION_TAG_MAP[403]],
                    ECKey(
                        binascii.unhexlify(
                            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
                        ),
                        None,
                        None,
                    ),
                ),
                "cbor": binascii.unhexlify(
                    "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
                ),
                "descriptor": "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
                "descriptor_checksum": "#8fhd9pwu",
            },
            {
                "test": "Example/Test Vector 2 (P2SH-P2WPKH output with the specified public key)",
                "item": Output(
                    [SCRIPT_EXPRESSION_TAG_MAP[400], SCRIPT_EXPRESSION_TAG_MAP[404]],
                    ECKey(
                        binascii.unhexlify(
                            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
                        ),
                        None,
                        None,
                    ),
                ),
                "cbor": binascii.unhexlify(
                    "d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
                ),
                "descriptor": "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
                "descriptor_checksum": "#qkrrc7je",
            },
            {
                "test": "Example/Test Vector 3 (P2SH 2-of-2 multisig output with keys in the specified order)",
                "item": Output(
                    [SCRIPT_EXPRESSION_TAG_MAP[400], SCRIPT_EXPRESSION_TAG_MAP[406]],
                    MultiKey(
                        2,
                        [
                            ECKey(
                                binascii.unhexlify(
                                    "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"
                                ),
                                None,
                                None,
                            ),
                            ECKey(
                                binascii.unhexlify(
                                    "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
                                ),
                                None,
                                None,
                            ),
                        ],
                        [],
                    ),
                ),
                "cbor": binascii.unhexlify(
                    "d90190d90196a201020282d90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01d90132a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
                ),
                "descriptor": "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
                "descriptor_checksum": "#y9zthqta",
            },
            {
                "test": "Example/Test Vector 4 (set of P2PKH outputs derived from this key by /1/*, but additionally specifies that the specified xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0')",
                "item": Output(
                    [SCRIPT_EXPRESSION_TAG_MAP[403]],
                    HDKey(
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
                ),
                "cbor": binascii.unhexlify(
                    "d90193d9012fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2906d90130a20186182cf500f500f5021ad34db33f07d90130a1018401f480f4081a78412e3a"
                ),
                "descriptor": "pkh([d34db33f/44'/0'/0']xpub6CY2xt3mvQejPFUw26CychtL4GMq1yp41aMW2U27mvThqefpZYwXpGscV26JuVj13Fpg4kgSENheUSbTqm5f8z25zrhXpPVss5zWeMGnAKR/1/*)",
                "descriptor_checksum": "#tgg7npaw",
            },
            {
                "test": "Example/Test Vector 5 (set of 1-of-2 P2WSH multisig outputs where the first multisig key is the 1/0/i child of the first specified xpub and the second multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range)",
                "item": Output(
                    [SCRIPT_EXPRESSION_TAG_MAP[401], SCRIPT_EXPRESSION_TAG_MAP[406]],
                    MultiKey(
                        1,
                        [],
                        [
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
                                    ),
                                    "origin": Keypath([], None, 0),
                                    "children": Keypath(
                                        [
                                            PathComponent(1, False),
                                            PathComponent(0, False),
                                            PathComponent(None, False),
                                        ],
                                        None,
                                        None,
                                    ),
                                }
                            ),
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
                                    ),
                                    "origin": Keypath(
                                        [PathComponent(0, False)],
                                        binascii.unhexlify("bd16bee5"),
                                        None,
                                    ),
                                    "children": Keypath(
                                        [
                                            PathComponent(0, False),
                                            PathComponent(0, False),
                                            PathComponent(None, False),
                                        ],
                                        None,
                                        None,
                                    ),
                                }
                            ),
                        ],
                    ),
                ),
                "cbor": binascii.unhexlify(
                    "d90191d90196a201010282d9012fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d90130a20180030007d90130a1018601f400f480f4d9012fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d90130a2018200f4021abd16bee507d90130a1018600f400f480f4"
                ),
                "descriptor": "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
                "descriptor_checksum": "#t2zpj2eu",
            },
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(
                Output.from_cbor(row["cbor"]),
                row["item"],
                msg="\nFailed: %s" % row["test"],
            )

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(
                row["item"].to_cbor(), row["cbor"], msg="\nFailed: %s" % row["test"]
            )

    def test_descriptor(self):
        for row in self.table():
            self.assertEqual(
                row["item"].descriptor(False),
                row["descriptor"],
                msg="\nFailed: %s" % row["test"],
            )
            self.assertEqual(
                row["item"].descriptor(True),
                row["descriptor"] + row["descriptor_checksum"],
                msg="\nFailed: %s" % row["test"],
            )
