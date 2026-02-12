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

import io
import binascii
from unittest import TestCase
from urtypes.cbor.decoder import Decoder, InvalidCborError

class DecoderTestCase(TestCase):
    def test_indefinite_bytestring(self):
        cbor = binascii.unhexlify("5f420102420304ff")
        decoder = Decoder(io.BytesIO(cbor))
        self.assertEqual(decoder.decode(), b"\x01\x02\x03\x04")

    def test_indefinite_textstring(self):
        cbor = binascii.unhexlify("7f62686963746865ff")
        decoder = Decoder(io.BytesIO(cbor))
        self.assertEqual(decoder.decode(), "hithe")

    def test_indefinite_list(self):
        cbor = binascii.unhexlify("9f010203ff")
        decoder = Decoder(io.BytesIO(cbor))
        self.assertEqual(decoder.decode(), [1, 2, 3])

    def test_indefinite_map(self):
        cbor = binascii.unhexlify("bf616101616202ff")
        decoder = Decoder(io.BytesIO(cbor))
        self.assertEqual(decoder.decode(), {"a": 1, "b": 2})

    def test_exceptions(self):
        def run_test(data):
            error = False
            try:
                Decoder(io.BytesIO(data)).decode()
                # print("FAIL:", data)
            except InvalidCborError as e:
                # print("PASS:", e)
                error = True
            assert error == True

        run_test(bytes([0x42, 0xAA])) # Expected 2 bytes, got 1 bytes instead
        run_test(bytes([0x59, 0x00])) # Expected 2 bytes, got 1 bytes instead
        run_test(bytes([0x5F, 0x61, 0x41, 0xFF])) # Wrong chunk type
        run_test(bytes([0xFF])) # Invalid BREAK code occurred


    def test_minimal_cbor_decoder(self):

        def _decode(val):
            dec = Decoder(io.BytesIO(val))
            return dec.decode()

        assert _decode(b'\x1a\x00\x01\x11\x70') == 0x11170
        assert _decode(b'\x1b\x00\x00\x00\x01\x02\x03\x04\x05') == 0x102030405
        assert _decode(b'\x00') == 0
        assert _decode(b'\x01') == 1
        assert _decode(b"\x17") == 23
        assert _decode(b"\x18\x18") == 24
        assert _decode(b"\x18\xff") == 255
        assert _decode(b"\x19\x01\x00") == 256
        assert _decode(b"\x19\xff\xff") == 65535
        assert _decode(b"\x1a\x00\x01\x00\x00") == 65536
        assert _decode(b"\x40") == b""
        assert _decode(b"\x41a") == b"a"
        assert _decode(b"\x57" + b"a" * 23) == b"a" * 23
        assert _decode(b"\x58\x18" + b"a" * 24) == b"a" * 24
        assert _decode(b"\x80") == []
        assert _decode(b"\x97" + b"\x00" * 23) == [0] * 23
        assert _decode(b"\x98\x18" + b"\x00" * 24) == [0] * 24

