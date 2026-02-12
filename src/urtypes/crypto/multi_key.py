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

from ..registry import RegistryItem


class MultiKey(RegistryItem):
    def __init__(self, threshold, ec_keys, hd_keys):
        self.threshold = threshold
        self.ec_keys = ec_keys
        self.hd_keys = hd_keys

    @classmethod
    def registry_type(cls):
        return None

    def to_data_item(self):
        from ..cbor.data import DataItem

        m = {1: self.threshold}
        out = []

        append = out.append

        for k in self.ec_keys:
            append(DataItem(k.registry_type().tag, k.to_data_item()))
        for k in self.hd_keys:
            append(DataItem(k.registry_type().tag, k.to_data_item()))

        m[2] = out
        return m

    @classmethod
    def from_data_item(cls, item):
        from .hd_key import HDKey, CRYPTO_HDKEY
        from .ec_key import ECKey, CRYPTO_ECKEY

        _map = item.map
        threshold = _map[1]
        keys = _map[2]
        ec_keys = []
        hd_keys = []
        for key in keys:
            if key.tag == CRYPTO_HDKEY.tag:
                hd_keys.append(HDKey.from_data_item(key))
            elif key.tag == CRYPTO_ECKEY.tag:
                ec_keys.append(ECKey.from_data_item(key))
        return cls(threshold, ec_keys, hd_keys)
