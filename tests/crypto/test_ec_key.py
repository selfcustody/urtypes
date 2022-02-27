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
from urtypes.crypto import ECKey


class ECKeyTestCase(TestCase):
    def table(self):
        return [
            {
                "test": "Example/Test Vector 1 (private key)",
                "item": ECKey(
                    binascii.unhexlify(
                        "8c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa"
                    ),
                    None,
                    True,
                ),
                "cbor": binascii.unhexlify(
                    "a202f50358208c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa"
                ),
            },
            {
                "test": "Example/Test Vector 1 (public key)",
                "item": ECKey(
                    binascii.unhexlify(
                        "03bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f"
                    ),
                    None,
                    None,
                ),
                "cbor": binascii.unhexlify(
                    "a103582103bec5163df25d8703150c3a1804eac7d615bb212b7cc9d7ff937aa8bd1c494b7f"
                ),
            },
        ]

    def test_from_cbor(self):
        for row in self.table():
            self.assertEqual(ECKey.from_cbor(row["cbor"]), row["item"])

    def test_to_cbor(self):
        for row in self.table():
            self.assertEqual(row["item"].to_cbor(), row["cbor"])
