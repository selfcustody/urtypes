# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun
# Copyright (c) 2015 Sokolov Yura
# Copyright (c) 2013 Fritz Grimpen

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
# coding: utf-8

from .data import DataItem


class InvalidCborError(Exception):
    pass


class _Break(InvalidCborError):
    def __init__(self):
        super().__init__("Invalid BREAK code occurred")


class Decoder:
    def __init__(self, _input):
        self.input = _input

    def decode(self):
        mtype, ainfo = self._decode_ibyte()

        if mtype == 0:
            return self.decode_integer(ainfo, False)
        if mtype == 1:
            return self.decode_integer(ainfo, True)
        if mtype == 2:
            return self.decode_bytestring(ainfo)
        if mtype == 3:
            return self.decode_textstring(ainfo)
        if mtype == 4:
            return self.decode_list(ainfo)
        if mtype == 5:
            return self.decode_dict(ainfo)
        if mtype == 6:
            return self.decode_tagging(ainfo)
        if mtype == 7:
            return self.decode_other(ainfo)

        raise InvalidCborError("Invalid major type")

    def decode_integer(self, ainfo, sign=False):
        res = self._decode_length(ainfo)
        if sign:
            return -1 - res
        return res

    def _decode_indefinite_string(self, expected_mtype):
        res = bytearray()
        while True:
            mtype, ainfo = self._decode_ibyte()
            if mtype == 7 and ainfo == 31:
                break
            if mtype != expected_mtype:
                raise InvalidCborError("Wrong chunk type")
            chunk = self.decode_bytestring(ainfo)
            res.extend(chunk)
        return res

    def decode_bytestring(self, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            return bytes(self._decode_indefinite_string(2))
        return self._read(length)

    def decode_textstring(self, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            return self._decode_indefinite_string(3).decode("utf-8")
        return self._read(length).decode("utf-8")

    def decode_list(self, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            res = []
            while True:
                try:
                    res.append(self.decode())
                except _Break:
                    break
            return res
        res = [None] * length
        for n in range(length):
            res[n] = self.decode()
        return res

    def decode_dict(self, ainfo):
        length = self._decode_length(ainfo)
        res = {}
        if length is None:
            try:
                while True:
                    key = self.decode()
                    value = self.decode()
                    res[key] = value
            except _Break:
                pass
            return res
        for _ in range(length):
            key = self.decode()
            value = self.decode()
            res[key] = value
        return res

    def decode_tagging(self, ainfo):
        tag = self._decode_length(ainfo)
        return DataItem(tag, self.decode())

    # def decode_half_float(self):
    #     import struct

    #     half = struct.unpack(">H", self._read(2))[0]
    #     valu = (half & 0x7FFF) << 13 | (half & 0x8000) << 16
    #     if (half & 0x7C00) != 0x7C00:
    #         import math

    #         return math.ldexp(struct.unpack("!f", struct.pack("!I", valu))[0], 112)
    #     return struct.unpack("!f", struct.pack("!I", valu | 0x7F800000))[0]

    # def decode_single_float(self):
    #     import struct

    #     return struct.unpack(">f", self._read(4))[0]

    # def decode_double_float(self):
    #     import struct

    #     return struct.unpack(">d", self._read(8))[0]

    def decode_other(self, ainfo):
        if ainfo == 20:
            return False
        if ainfo == 21:
            return True
        if ainfo == 22:
            return None
        # if ainfo == 23:
        #     from .data import Undefined

        #     return Undefined
        # if ainfo == 25:
        #     return self.decode_half_float()
        # if ainfo == 26:
        #     return self.decode_single_float()
        # if ainfo == 27:
        #     return self.decode_double_float()
        raise _Break()

    def _decode_ibyte(self):
        byte = self._read(1)[0]
        return (byte >> 5), (byte & 0x1F)

    def _decode_length(self, ainfo):
        if ainfo < 24:
            return ainfo
        if ainfo == 24:
            return self._read(1)[0]
        if ainfo == 25:
            return int.from_bytes(self._read(2), "big")
        if ainfo == 26:
            return int.from_bytes(self._read(4), "big")
        if ainfo == 27:
            return int.from_bytes(self._read(8), "big")
        if ainfo == 31:
            return None
        raise InvalidCborError("Invalid additional information {}".format(ainfo))

    def _read(self, n):
        m = self.input.read(n)
        if len(m) != n:
            raise InvalidCborError(
                "Expected {} bytes, got {} bytes instead".format(n, len(m))
            )
        return m


__all__ = ("InvalidCborError", "Decoder")
