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
from unittest import TestCase
from urtypes.cbor.encoder import Encoder

class EncoderTestCase(TestCase):
    def test_minimal_cbor_encoder(self):

        def _encode(val):
            enc = Encoder(io.BytesIO())
            enc.encode(val)

            # get cbor encoded data
            enc.output.seek(0)
            return enc.output.read()

        assert _encode(0x11170) == b'\x1a\x00\x01\x11\x70'
        assert _encode(0x102030405) == b'\x1b\x00\x00\x00\x01\x02\x03\x04\x05'
        assert _encode(0) == b'\x00'
        assert _encode(1) == b'\x01'
        assert _encode(23) == b"\x17"
        assert _encode(24) == b"\x18\x18"
        assert _encode(255) == b"\x18\xff"
        assert _encode(256) == b"\x19\x01\x00"
        assert _encode(65535) == b"\x19\xff\xff"
        assert _encode(65536) == b"\x1a\x00\x01\x00\x00"

        # assert _encode(-1) == b"\x20"
        # assert _encode(-23) == b"\x36"
        # assert _encode(-24) == b"\x37"
        # assert _encode(-255) == b"\x38\xfe"
        # assert _encode(-256) == b"\x38\xff"
        # assert _encode(-65535) == b"\x39\xff\xfe"
        # assert _encode(-65536) == b"\x39\xff\xff"

        assert _encode(b"") == b"\x40"
        assert _encode(b"a") == b"\x41a"
        assert _encode(b"a" * 23) == b"\x57" + b"a" * 23
        assert _encode(b"a" * 24) == b"\x58\x18" + b"a" * 24
        assert _encode([]) == b"\x80"
        assert _encode([0] * 23) == b"\x97" + b"\x00" * 23
        assert _encode([0] * 24) == b"\x98\x18" + b"\x00" * 24
