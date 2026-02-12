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

from .data import Tagging, Mapping


class EncoderError(Exception):
    pass


class Encoder:
    def __init__(self, output):
        self.output = output

    def encode(self, val):
        if isinstance(val, bytes):
            self.encode_bytestring(val)
        elif isinstance(val, str):
            self.encode_textstring(val)
        # elif isinstance(val, float):
        #     self.encode_float(val)
        elif isinstance(val, bool):
            self.encode_boolean(val)
        elif isinstance(val, int):
            self.encode_unsigned(val)
        elif isinstance(val, list):
            self.encode_list(val)
        elif isinstance(val, dict):
            self.encode_dict(val)
        elif isinstance(val, Tagging):
            self.encode_tagging(val)
        # elif val is Undefined:
        #     self.encode_undefined()
        # elif val is None:
        #     self.encode_null()
        elif isinstance(val, Mapping):
            val = val.map
            self.encode(val)
        else:
            raise EncoderError("Unsupported type")

    def encode_list(self, _list):
        _write_type_and_length(self.output, 4, len(_list))
        for elem in _list:
            self.encode(elem)

    def encode_dict(self, _dict):
        _write_type_and_length(self.output, 5, len(_dict))
        for key, value in _dict.items():
            self.encode(key)
            self.encode(value)

    def encode_bytestring(self, bytestring):
        _write_type_and_length(self.output, 2, len(bytestring))
        self.output.write(bytestring)

    def encode_textstring(self, textstring):
        string_ = textstring.encode("utf-8")
        _write_type_and_length(self.output, 3, len(string_))
        self.output.write(string_)

    # def encode_float(self, _float):
    #     self._write(b"\xfb")
    #     self._write(struct.pack(">d", _float))

    def encode_unsigned(self, value):
        _write_type_and_length(self.output, 0, value)

    # def encode_integer(self, value):
    #     if value >= 0:
    #         self.encode_unsigned(value)
    #     else:
    #         self.encode_negative(-value - 1)

    # def encode_negative(self, value):
    #     _write_type_and_length(self.output, 1, -value - 1)

    def encode_tagging(self, tagging):
        _write_type_and_length(self.output, 6, tagging.tag)
        self.encode(tagging.obj)

    def encode_boolean(self, boolean):
        if boolean is True:
            _write_type_and_length(self.output, 7, 21)
        else:
            _write_type_and_length(self.output, 7, 20)

    # def encode_null(self):
    #     self._write(_encode_ibyte(7, 22))

    # def encode_undefined(self):
    #     self._write(b"\xf7")

    # def _write(self, val):
    #     self.output.write(val)


def _write_type_and_length(out, major, value):
    major <<= 5

    if value < 24:  # 0 bytes payload
        out.write(bytes((major | value,)))
        return

    if value <= 0xFF:  # 1 byte
        out.write(bytes((major | 24, value)))
        return

    if value <= 0xFFFF:  # 2 bytes
        out.write(
            bytes(
                (
                    major | 25,
                    (value >> 8) & 0xFF,
                    value & 0xFF,
                )
            )
        )
        return

    if value <= 0xFFFFFFFF:  # 4 bytes
        out.write(
            bytes(
                (
                    major | 26,
                    (value >> 24) & 0xFF,
                    (value >> 16) & 0xFF,
                    (value >> 8) & 0xFF,
                    value & 0xFF,
                )
            )
        )
        return

    # 8 bytes
    out.write(
        bytes(
            (
                major | 27,
                (value >> 56) & 0xFF,
                (value >> 48) & 0xFF,
                (value >> 40) & 0xFF,
                (value >> 32) & 0xFF,
                (value >> 24) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            )
        )
    )
    return


__all__ = ("Encoder", "EncoderError")
