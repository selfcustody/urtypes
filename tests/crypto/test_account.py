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
    Account,
    Output,
    SCRIPT_EXPRESSION_TAG_MAP,
    HDKey,
    Keypath,
    PathComponent,
)


class AccountTestCase(TestCase):
    def table(self):
        return [
            {
                "test": "Example/Test Vector (#0 account for BTC mainnet for the following BIP39 seed: shield group erode awake lock sausage cash glare wave crew flame glove)",
                "item": Account(
                    binascii.unhexlify("37b5eed4"),
                    [
                        Output(
                            [SCRIPT_EXPRESSION_TAG_MAP[403]],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "03eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f478199884d9dd32"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "6456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b"
                                    ),
                                    "origin": Keypath(
                                        [
                                            PathComponent(44, True),
                                            PathComponent(0, True),
                                            PathComponent(0, True),
                                        ],
                                        None,
                                        None,
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "99f9cdf7"
                                    ),
                                }
                            ),
                        ),
                        Output(
                            [
                                SCRIPT_EXPRESSION_TAG_MAP[400],
                                SCRIPT_EXPRESSION_TAG_MAP[404],
                            ],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "02c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b69"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "9d2f86043276f9251a4a4f577166a5abeb16b6ec61e226b5b8fa11038bfda42d"
                                    ),
                                    "origin": Keypath(
                                        [
                                            PathComponent(49, True),
                                            PathComponent(0, True),
                                            PathComponent(0, True),
                                        ],
                                        None,
                                        None,
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "a80f7cdb"
                                    ),
                                }
                            ),
                        ),
                        Output(
                            [SCRIPT_EXPRESSION_TAG_MAP[404]],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "03fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "72ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a88"
                                    ),
                                    "origin": Keypath(
                                        [
                                            PathComponent(84, True),
                                            PathComponent(0, True),
                                            PathComponent(0, True),
                                        ],
                                        None,
                                        None,
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "0d5de1d7"
                                    ),
                                }
                            ),
                        ),
                        Output(
                            [SCRIPT_EXPRESSION_TAG_MAP[400]],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "035ccd58b63a2cdc23d0812710603592e7457573211880cb59b1ef012e168e059a"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "88d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34daeb1a23"
                                    ),
                                    "origin": Keypath(
                                        [PathComponent(45, True)], None, None
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "37b5eed4"
                                    ),
                                }
                            ),
                        ),
                        Output(
                            [
                                SCRIPT_EXPRESSION_TAG_MAP[400],
                                SCRIPT_EXPRESSION_TAG_MAP[401],
                            ],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "032c78ebfcabdac6d735a0820ef8732f2821b4fb84cd5d6b26526938f90c050711"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "7953efe16a73e5d3f9f2d4c6e49bd88e22093bbd85be5a7e862a4b98a16e0ab6"
                                    ),
                                    "origin": Keypath(
                                        [
                                            PathComponent(48, True),
                                            PathComponent(0, True),
                                            PathComponent(0, True),
                                            PathComponent(1, True),
                                        ],
                                        None,
                                        None,
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "59b69b2a"
                                    ),
                                }
                            ),
                        ),
                        Output(
                            [SCRIPT_EXPRESSION_TAG_MAP[401]],
                            HDKey(
                                {
                                    "key": binascii.unhexlify(
                                        "0260563ee80c26844621b06b74070baf0e23fb76ce439d0237e87502ebbd3ca346"
                                    ),
                                    "chain_code": binascii.unhexlify(
                                        "2fa0e41c9dc43dc4518659bfcef935ba8101b57dbc0812805dd983bc1d34b813"
                                    ),
                                    "origin": Keypath(
                                        [
                                            PathComponent(48, True),
                                            PathComponent(0, True),
                                            PathComponent(0, True),
                                            PathComponent(2, True),
                                        ],
                                        None,
                                        None,
                                    ),
                                    "parent_fingerprint": binascii.unhexlify(
                                        "59b69b2a"
                                    ),
                                }
                            ),
                        ),
                    ],
                ),
                "cbor": binascii.unhexlify(
                    "a2011a37b5eed40286d90193d9012fa403582103eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f478199884d9dd320458206456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b06d90130a10186182cf500f500f5081a99f9cdf7d90190d90194d9012fa403582102c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b690458209d2f86043276f9251a4a4f577166a5abeb16b6ec61e226b5b8fa11038bfda42d06d90130a101861831f500f500f5081aa80f7cdbd90194d9012fa403582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d90130a101861854f500f500f5081a0d5de1d7d90190d9012fa4035821035ccd58b63a2cdc23d0812710603592e7457573211880cb59b1ef012e168e059a04582088d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34daeb1a2306d90130a10182182df5081a37b5eed4d90190d90191d9012fa4035821032c78ebfcabdac6d735a0820ef8732f2821b4fb84cd5d6b26526938f90c0507110458207953efe16a73e5d3f9f2d4c6e49bd88e22093bbd85be5a7e862a4b98a16e0ab606d90130a101881830f500f500f501f5081a59b69b2ad90191d9012fa40358210260563ee80c26844621b06b74070baf0e23fb76ce439d0237e87502ebbd3ca3460458202fa0e41c9dc43dc4518659bfcef935ba8101b57dbc0812805dd983bc1d34b81306d90130a101881830f500f500f502f5081a59b69b2a"
                ),
            }
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(Account.from_cbor(row["cbor"]), row["item"])

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(row["item"].to_cbor(), row["cbor"])
