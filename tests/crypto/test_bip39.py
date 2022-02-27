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
from urtypes.crypto import BIP39


class BIP39TestCase(TestCase):
    def table(self):
        return [
            {
                "test": "Example/Test Vector (16 byte (128-bit) seed, encoded as BIP39)",
                "item": BIP39(
                    [
                        "shield",
                        "group",
                        "erode",
                        "awake",
                        "lock",
                        "sausage",
                        "cash",
                        "glare",
                        "wave",
                        "crew",
                        "flame",
                        "glove",
                    ],
                    "en",
                ),
                "cbor": binascii.unhexlify(
                    "a2018c66736869656c646567726f75706565726f6465656177616b65646c6f636b6773617573616765646361736865676c6172656477617665646372657765666c616d6565676c6f76650262656e"
                ),
            }
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(BIP39.from_cbor(row["cbor"]), row["item"])

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(row["item"].to_cbor(), row["cbor"])
