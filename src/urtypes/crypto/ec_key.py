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

from ..registry import RegistryType, RegistryItem

CRYPTO_ECKEY = RegistryType("crypto-eckey", 306)


class ECKey(RegistryItem):
    def __init__(self, data, curve, private_key):
        self.data = data
        self.curve = curve
        self.private_key = private_key

    @classmethod
    def registry_type(cls):
        return CRYPTO_ECKEY

    def to_data_item(self):
        _map = {}
        if self.curve is not None:
            _map[1] = self.curve
        if self.private_key is not None:
            _map[2] = self.private_key
        _map[3] = self.data
        return _map

    @classmethod
    def from_data_item(cls, item):
        m = cls.mapping(item)
        return cls(
            m[3],  # data
            m.get(1),  # curve
            m.get(2),  # pkey
        )

    def descriptor_key(self):
        import binascii

        return binascii.hexlify(self.data).decode()
