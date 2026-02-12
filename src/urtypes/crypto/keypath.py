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

CRYPTO_KEYPATH = RegistryType("crypto-keypath", 304)


class Keypath(RegistryItem):
    def __init__(self, components, source_fingerprint, depth):
        self.components = components
        self.source_fingerprint = source_fingerprint
        self.depth = depth

    @classmethod
    def registry_type(cls):
        return CRYPTO_KEYPATH

    def path(self):
        comps = self.components
        if not comps:
            return ""

        return "/".join(
            (("*" if c.wildcard else str(c.index)) + ("'" if c.hardened else ""))
            for c in comps
        )

    def to_data_item(self):
        _map = {}
        comps = self.components

        out = []
        for c in comps:
            out.append([] if c.wildcard else c.index)
            out.append(c.hardened)

        _map[1] = out

        fp = self.source_fingerprint
        if fp is not None:
            _map[2] = int.from_bytes(fp, "big")

        d = self.depth
        if d is not None:
            _map[3] = d

        return _map

    @classmethod
    def from_data_item(cls, item):
        m = cls.mapping(item)
        get = m.get

        raw = get(1)
        components = []

        if raw:
            it = iter(raw)
            for path, hardened in zip(it, it):
                components.append(
                    PathComponent(path if isinstance(path, int) else None, hardened)
                )

        fp = get(2)
        if fp is not None:
            fp = fp.to_bytes(4, "big")

        return cls(
            components,
            fp,
            get(3),  # depth
        )


class PathComponent:
    def __init__(self, index, hardened):
        if index is not None and (index & 0x80000000) != 0:
            raise ValueError("Invalid index - most significant bit cannot be set")

        self.index = index
        self.hardened = hardened
        self.wildcard = index is None
