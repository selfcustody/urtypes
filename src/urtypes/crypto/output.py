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


class ScriptExpression:
    def __init__(self, tag, expression):
        self.tag = tag
        self.expression = expression


SCRIPT_EXPRESSION_TAG_MAP = {
    307: ScriptExpression(307, "addr"),
    400: ScriptExpression(400, "sh"),
    401: ScriptExpression(401, "wsh"),
    402: ScriptExpression(402, "pk"),
    403: ScriptExpression(403, "pkh"),
    404: ScriptExpression(404, "wpkh"),
    405: ScriptExpression(405, "combo"),
    406: ScriptExpression(406, "multi"),
    407: ScriptExpression(407, "sortedmulti"),
    408: ScriptExpression(408, "raw"),
    409: ScriptExpression(409, "tr"),
    410: ScriptExpression(410, "cosigner"),
}

CRYPTO_OUTPUT = RegistryType("crypto-output", 308)


class Output(RegistryItem):
    def __init__(self, script_expressions, crypto_key):
        self.script_expressions = script_expressions
        self.crypto_key = crypto_key

    @classmethod
    def registry_type(cls):
        return CRYPTO_OUTPUT

    def descriptor(self, include_checksum=True):
        from .multi_key import MultiKey

        parts = []

        for se in self.script_expressions:
            parts.append(se.expression)
            parts.append("(")

        ck = self.crypto_key
        if isinstance(ck, MultiKey):
            parts.append(str(ck.threshold))
            parts.append(",")

            first = True
            for key in ck.ec_keys:
                if not first:
                    parts.append(",")
                parts.append(key.descriptor_key())
                first = False
            for key in ck.hd_keys:
                if not first:
                    parts.append(",")
                parts.append(key.descriptor_key())
                first = False
        else:
            parts.append(ck.descriptor_key())

        parts.extend(")" for _ in self.script_expressions)

        d = "".join(parts)

        if include_checksum:
            return d + "#" + descriptor_checksum(d)
        return d

    def hd_key(self):
        from .hd_key import HDKey

        ck = self.crypto_key
        return ck if isinstance(ck, HDKey) else None

    def ec_key(self):
        from .ec_key import ECKey

        ck = self.crypto_key
        return ck if isinstance(ck, ECKey) else None

    def multi_key(self):
        from .multi_key import MultiKey

        ck = self.crypto_key
        return ck if isinstance(ck, MultiKey) else None

    def to_data_item(self):
        from ..cbor.data import DataItem

        ck = self.crypto_key
        item = DataItem(None, ck.to_data_item())

        rt = ck.registry_type()
        if rt is not None:
            item.tag = rt.tag

        i = len(self.script_expressions)
        while i:
            i -= 1
            tag = self.script_expressions[i].tag
            item = DataItem(tag, item) if item.tag is not None else item
            item.tag = tag

        return item

    @classmethod
    def from_data_item(cls, item):
        tmp = cls.mapping(item)
        script_expressions = []

        while True:
            tag = tmp.tag
            se = SCRIPT_EXPRESSION_TAG_MAP.get(tag)
            if se is None:
                break

            script_expressions.append(se)

            m = tmp.map
            if not hasattr(m, "tag"):
                break
            tmp = m

        if script_expressions and script_expressions[-1].expression in (
            "multi",
            "sortedmulti",
        ):
            from .multi_key import MultiKey

            return cls(script_expressions, MultiKey.from_data_item(tmp))

        from .hd_key import HDKey, CRYPTO_HDKEY

        if tmp.tag == CRYPTO_HDKEY.tag:
            return cls(script_expressions, HDKey.from_data_item(tmp))

        from .ec_key import ECKey

        return cls(script_expressions, ECKey.from_data_item(tmp))


def polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7FFFFFFFF) << 5) ^ val
    if c0 & 1:
        c ^= 0xF5DEE51989
    if c0 & 2:
        c ^= 0xA9FDCA3312
    if c0 & 4:
        c ^= 0x1BAB10E32D
    if c0 & 8:
        c ^= 0x3706B1677A
    if c0 & 16:
        c ^= 0x644D626FFD
    return c


def descriptor_checksum(descriptor):
    INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    c = 1
    cls = 0
    clscount = 0
    for ch in descriptor:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            return ""
        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = polymod(c, cls)
    for _ in range(8):
        c = polymod(c, 0)
    c ^= 1
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    checksum = ""
    for i in range(8):
        checksum += CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31]
    return checksum
