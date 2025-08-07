# coding: utf-8
# PyDERASN -- Python ASN.1 DER/CER/BER codec with abstract structures
# Copyright (C) 2017-2022 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.

from copy import copy
from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from importlib import import_module
from io import BytesIO
from operator import attrgetter
from os import environ
from os import urandom
from random import random
from string import ascii_letters
from string import digits
from string import printable
from string import whitespace
from time import mktime
from time import time
from unittest import TestCase
from unittest.mock import patch

from dateutil.tz import UTC
from hypothesis import assume
from hypothesis import given
from hypothesis import settings
from hypothesis.strategies import binary
from hypothesis.strategies import booleans
from hypothesis.strategies import composite
from hypothesis.strategies import data as data_strategy
from hypothesis.strategies import datetimes
from hypothesis.strategies import dictionaries
from hypothesis.strategies import integers
from hypothesis.strategies import just
from hypothesis.strategies import lists
from hypothesis.strategies import none
from hypothesis.strategies import one_of
from hypothesis.strategies import permutations
from hypothesis.strategies import sampled_from
from hypothesis.strategies import sets
from hypothesis.strategies import text
from hypothesis.strategies import tuples
from pickle import dumps as pickle_dumps
from pickle import HIGHEST_PROTOCOL as pickle_proto
from pickle import loads as pickle_loads

from pyderasn import _pp
from pyderasn import abs_decode_path
from pyderasn import Any
from pyderasn import BitString
from pyderasn import BMPString
from pyderasn import Boolean
from pyderasn import BoundsError
from pyderasn import Choice
from pyderasn import DecodeError
from pyderasn import DecodePathDefBy
from pyderasn import encode2pass
from pyderasn import encode_cer
from pyderasn import Enumerated
from pyderasn import EOC
from pyderasn import EOC_LEN
from pyderasn import ExceedingData
from pyderasn import GeneralizedTime
from pyderasn import GeneralString
from pyderasn import GraphicString
from pyderasn import hexdec
from pyderasn import hexenc
from pyderasn import IA5String
from pyderasn import Integer
from pyderasn import InvalidLength
from pyderasn import InvalidOID
from pyderasn import InvalidValueType
from pyderasn import len_decode
from pyderasn import len_encode
from pyderasn import LEN_YYMMDDHHMMSSZ
from pyderasn import LEN_YYYYMMDDHHMMSSDMZ
from pyderasn import LEN_YYYYMMDDHHMMSSZ
from pyderasn import LENINDEF
from pyderasn import LenIndefForm
from pyderasn import NotEnoughData
from pyderasn import Null
from pyderasn import NumericString
from pyderasn import ObjectIdentifier
from pyderasn import ObjNotReady
from pyderasn import ObjUnknown
from pyderasn import OctetString
from pyderasn import pp_console_row
from pyderasn import pprint
from pyderasn import PrintableString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import Set
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp
from pyderasn import tag_decode
from pyderasn import tag_encode
from pyderasn import tag_strip
from pyderasn import TagClassApplication
from pyderasn import TagClassContext
from pyderasn import TagClassPrivate
from pyderasn import TagClassUniversal
from pyderasn import TagFormConstructed
from pyderasn import TagFormPrimitive
from pyderasn import TagMismatch
from pyderasn import TeletexString
from pyderasn import UniversalString
from pyderasn import UTCTime
from pyderasn import UTF8String
from pyderasn import VideotexString
from pyderasn import VisibleString
import pyderasn


max_examples = environ.get("MAX_EXAMPLES")
settings.register_profile("local", settings(
    deadline=5000,
    **({"max_examples": int(max_examples)} if max_examples else {})
))
settings.load_profile("local")
LONG_TEST_MAX_EXAMPLES = settings().max_examples * 4

tag_classes = sampled_from((
    TagClassApplication,
    TagClassContext,
    TagClassPrivate,
    TagClassUniversal,
))
tag_forms = sampled_from((TagFormConstructed, TagFormPrimitive))
decode_path_strat = lists(integers(), max_size=3).map(
    lambda decode_path: tuple(str(dp) for dp in decode_path)
)
ctx_dummy = dictionaries(integers(), integers(), min_size=2, max_size=4).example()
copy_funcs = (
    copy,
    lambda obj: pickle_loads(pickle_dumps(obj, pickle_proto)),
)
self_module = import_module(__name__)


def register_class(klass):
    klassname = klass.__name__ + str(time()).replace(".", "")
    klass.__name__ = klassname
    klass.__qualname__ = klassname
    setattr(self_module, klassname, klass)


def assert_exceeding_data(self, call, junk):
    if len(junk) <= 0:
        return
    with self.assertRaisesRegex(ExceedingData, "%d trailing bytes" % len(junk)) as err:
        call()
    repr(err)


class TestHex(TestCase):
    @given(binary())
    def test_symmetric(self, data):
        self.assertEqual(hexdec(hexenc(data)), data)


class TestTagCoder(TestCase):
    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        tag_classes,
        tag_forms,
        integers(min_value=0, max_value=30),
        binary(max_size=5),
    )
    def test_short(self, klass, form, num, junk):
        raw = tag_encode(klass=klass, form=form, num=num)
        self.assertEqual(tag_decode(raw), (klass, form, num))
        self.assertEqual(len(raw), 1)
        self.assertEqual(
            tag_encode(klass=klass, form=form, num=0)[0],
            raw[0] & (1 << 7 | 1 << 6 | 1 << 5),
        )
        stripped, tlen, tail = tag_strip(memoryview(raw + junk))
        self.assertSequenceEqual(stripped.tobytes(), raw)
        self.assertEqual(tlen, len(raw))
        self.assertSequenceEqual(tail, junk)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        tag_classes,
        tag_forms,
        integers(min_value=31),
        binary(max_size=5),
    )
    def test_long(self, klass, form, num, junk):
        raw = tag_encode(klass=klass, form=form, num=num)
        self.assertEqual(tag_decode(raw), (klass, form, num))
        self.assertGreater(len(raw), 1)
        self.assertEqual(
            tag_encode(klass=klass, form=form, num=0)[0] | 31,
            raw[0],
        )
        self.assertEqual(raw[-1] & 0x80, 0)
        self.assertTrue(all(b & 0x80 > 0 for b in raw[1:-1]))
        stripped, tlen, tail = tag_strip(memoryview(raw + junk))
        self.assertSequenceEqual(stripped.tobytes(), raw)
        self.assertEqual(tlen, len(raw))
        self.assertSequenceEqual(tail, junk)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(integers(min_value=31))
    def test_unfinished_tag(self, num):
        raw = bytearray(tag_encode(num=num))
        for i in range(1, len(raw)):
            raw[i] |= 0x80
        with self.assertRaisesRegex(DecodeError, "unfinished tag"):
            tag_strip(bytes(raw))

    def test_go_vectors_valid(self):
        for data, (eklass, etag, elen, eform) in (
                (b"\x80\x01", (TagClassContext, 0, 1, TagFormPrimitive)),
                (b"\xa0\x01", (TagClassContext, 0, 1, TagFormConstructed)),
                (b"\x02\x00", (TagClassUniversal, 2, 0, TagFormPrimitive)),
                (b"\xfe\x00", (TagClassPrivate, 30, 0, TagFormConstructed)),
                (b"\x1f\x1f\x00", (TagClassUniversal, 31, 0, TagFormPrimitive)),
                (b"\x1f\x81\x00\x00", (TagClassUniversal, 128, 0, TagFormPrimitive)),
                (b"\x1f\x81\x80\x01\x00", (TagClassUniversal, 0x4001, 0, TagFormPrimitive)),
                (b"\x00\x81\x80", (TagClassUniversal, 0, 128, TagFormPrimitive)),
                (b"\x00\x82\x01\x00", (TagClassUniversal, 0, 256, TagFormPrimitive)),
                (b"\xa0\x84\x7f\xff\xff\xff", (TagClassContext, 0, 0x7fffffff, TagFormConstructed)),
        ):
            tag, _, len_encoded = tag_strip(memoryview(data))
            klass, form, num = tag_decode(tag)
            _len, _, tail = len_decode(len_encoded)
            self.assertSequenceEqual(tail, b"")
            self.assertEqual(klass, eklass)
            self.assertEqual(num, etag)
            self.assertEqual(_len, elen)
            self.assertEqual(form, eform)

    def test_go_vectors_invalid(self):
        for data in (
                b"\x00\x83\x01\x00",
                b"\x1f\x85",
                b"\x30\x80",
                b"\xa0\x82\x00\xff",
                b"\xa0\x81\x7f",
        ):
            with self.assertRaises(DecodeError):
                _, _, len_encoded = tag_strip(memoryview(data))
                len_decode(len_encoded)

    @given(
        integers(min_value=0, max_value=127),
        integers(min_value=0, max_value=2),
    )
    def test_long_instead_of_short(self, l, dummy_num):
        octets = (b"\x00" * dummy_num) + bytes([l])
        octets = bytes([(dummy_num + 1) | 0x80]) + octets
        with self.assertRaises(DecodeError):
            len_decode(octets)

    @given(tag_classes, tag_forms, integers(min_value=31))
    def test_leading_zero_byte(self, klass, form, num):
        raw = tag_encode(klass=klass, form=form, num=num)
        raw = b"".join((raw[:1], b"\x80", raw[1:]))
        with self.assertRaisesRegex(DecodeError, "leading zero byte"):
            tag_strip(raw)

    @given(tag_classes, tag_forms, integers(max_value=30, min_value=0))
    def test_unexpected_long_form(self, klass, form, num):
        raw = bytes([klass | form | 31, num])
        with self.assertRaisesRegex(DecodeError, "unexpected long form"):
            tag_strip(raw)


class TestLenCoder(TestCase):
    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        integers(min_value=0, max_value=127),
        binary(max_size=5),
    )
    def test_short(self, l, junk):
        raw = len_encode(l) + junk
        decoded, llen, tail = len_decode(memoryview(raw))
        self.assertEqual(decoded, l)
        self.assertEqual(llen, 1)
        self.assertEqual(len(raw), 1 + len(junk))
        self.assertEqual(tail.tobytes(), junk)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        integers(min_value=128),
        binary(max_size=5),
    )
    def test_long(self, l, junk):
        raw = len_encode(l) + junk
        decoded, llen, tail = len_decode(memoryview(raw))
        self.assertEqual(decoded, l)
        self.assertEqual((llen - 1) | 0x80, raw[0])
        self.assertEqual(llen, len(raw) - len(junk))
        self.assertNotEqual(raw[1], 0)
        self.assertSequenceEqual(tail.tobytes(), junk)

    def test_empty(self):
        with self.assertRaises(NotEnoughData):
            len_decode(b"")

    @given(integers(min_value=128))
    def test_stripped(self, _len):
        with self.assertRaises(NotEnoughData):
            len_decode(len_encode(_len)[:-1])


text_printable = text(alphabet=printable, min_size=1)


@composite
def text_letters(draw):
    result = draw(text(alphabet=ascii_letters, min_size=1))
    return result


class CommonMixin(object):
    def test_tag_default(self):
        obj = self.base_klass()
        self.assertEqual(obj.tag, obj.tag_default)

    def test_simultaneous_impl_expl(self):
        with self.assertRaises(ValueError):
            self.base_klass(impl=b"whatever", expl=b"whenever")

    @given(binary(min_size=1), integers(), integers(), integers())
    def test_decoded(self, impl, offset, llen, vlen):
        obj = self.base_klass(impl=impl, _decoded=(offset, llen, vlen))
        self.assertEqual(obj.offset, offset)
        self.assertEqual(obj.llen, llen)
        self.assertEqual(obj.vlen, vlen)
        self.assertEqual(obj.tlen, len(impl))
        self.assertEqual(obj.tlvlen, obj.tlen + obj.llen + obj.vlen)

    @given(binary(min_size=1))
    def test_impl_inherited(self, impl_tag):
        class Inherited(self.base_klass):
            impl = impl_tag
        obj = Inherited()
        self.assertSequenceEqual(obj.impl, impl_tag)
        self.assertFalse(obj.expled)
        if obj.ready:
            tag_class, _, tag_num = tag_decode(impl_tag)
            self.assertEqual(obj.tag_order, (tag_class, tag_num))

    @given(binary(min_size=1))
    def test_expl_inherited(self, expl_tag):
        class Inherited(self.base_klass):
            expl = expl_tag
        obj = Inherited()
        self.assertSequenceEqual(obj.expl, expl_tag)
        self.assertTrue(obj.expled)
        if obj.ready:
            tag_class, _, tag_num = tag_decode(expl_tag)
            self.assertEqual(obj.tag_order, (tag_class, tag_num))

    def assert_copied_basic_fields(self, obj, obj_copied):
        self.assertEqual(obj, obj_copied)
        self.assertSequenceEqual(obj.tag, obj_copied.tag)
        self.assertEqual(obj.expl_tag, obj_copied.expl_tag)
        self.assertEqual(obj.default, obj_copied.default)
        self.assertEqual(obj.optional, obj_copied.optional)
        self.assertEqual(obj.offset, obj_copied.offset)
        self.assertEqual(obj.llen, obj_copied.llen)
        self.assertEqual(obj.vlen, obj_copied.vlen)
        if obj.ready:
            self.assertEqual(obj.tag_order, obj_copied.tag_order)


@composite
def boolean_values_strategy(draw, do_expl=False):
    value = draw(one_of(none(), booleans()))
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = draw(one_of(none(), booleans()))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, impl, expl, default, optional, _decoded)


class BooleanInherited(Boolean):
    pass


class TestBoolean(CommonMixin, TestCase):
    base_klass = Boolean

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            Boolean(123)
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = Boolean(default=Boolean(False), optional=optional)
        self.assertTrue(obj.optional)

    @given(booleans())
    def test_ready(self, value):
        obj = Boolean()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        repr(err.exception)
        obj = Boolean(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(booleans(), booleans(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        for klass in (Boolean, BooleanInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == bool(obj2), value1 == value2)
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(data_strategy())
    def test_call(self, d):
        for klass in (Boolean, BooleanInherited):
            (
                value_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(boolean_values_strategy())
            obj_initial = klass(
                value_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial or False,
                _decoded_initial,
            )
            (
                value,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(boolean_values_strategy(do_expl=impl_initial is None))
            obj = obj_initial(value, impl, expl, default, optional)
            if obj.ready:
                value_expected = default if value is None else value
                value_expected = (
                    default_initial if value_expected is None
                    else value_expected
                )
                self.assertEqual(obj, value_expected)
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            self.assertEqual(
                obj.default,
                default_initial if default is None else default,
            )
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)

    @given(boolean_values_strategy())
    def test_copy(self, values):
        for klass in (Boolean, BooleanInherited):
            obj = klass(*values)
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)

    @given(
        booleans(),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, value, tag_impl):
        obj = Boolean(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])
        with self.assertRaises(NotEnoughData):
            obj.decode(encode2pass(obj)[:-1])

    @given(
        booleans(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = Boolean(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])
        with self.assertRaises(NotEnoughData):
            obj.decode(encode2pass(obj)[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Boolean().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_expl_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Boolean(expl=Boolean.tag_default).decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Boolean().decode(
                Boolean.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_expl_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Boolean(expl=Boolean.tag_default).decode(
                Boolean.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        boolean_values_strategy(),
        booleans(),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
    )
    def test_symmetric(self, values, value, tag_expl, offset, tail_junk, decode_path):
        for klass in (Boolean, BooleanInherited):
            _, _, _, default, optional, _decoded = values
            obj = klass(
                value=value,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled.encode(),
            )
            obj_expled_hex_encoded = obj_expled.hexencode()
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.hexdecode(
                obj_expled_hex_encoded + hexenc(tail_junk),
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertEqual(bool(obj_decoded), bool(obj_expled))
            self.assertEqual(bool(obj_decoded), bool(obj))
            self.assertSequenceEqual(obj_decoded.hexencode(), obj_expled_hex_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            assert_exceeding_data(
                self,
                lambda: obj_expled.hexdecod(obj_expled_hex_encoded + hexenc(tail_junk)),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                hexdec(obj_expled_hex_encoded) + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj, obj_decoded)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @given(integers(min_value=2, max_value=10))
    def test_invalid_len(self, l):
        with self.assertRaises(InvalidLength):
            Boolean().decode(b"".join((
                Boolean.tag_default,
                len_encode(l),
                b"\x00" * l,
            )))

    @given(integers(min_value=0 + 1, max_value=255 - 1))
    def test_ber_value(self, value):
        with self.assertRaisesRegex(DecodeError, "unacceptable Boolean value"):
            Boolean().decode(b"".join((
                Boolean.tag_default,
                len_encode(1),
                bytes([value]),
            )))
        encoded = b"".join((Boolean.tag_default, len_encode(1), bytes([value])))
        obj, _ = Boolean().decode(encoded, ctx={"bered": True})
        list(Boolean().decode_evgen(encoded, ctx={"bered": True}))
        self.assertTrue(bool(obj))
        self.assertTrue(obj.ber_encoded)
        self.assertFalse(obj.lenindef)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertFalse(obj.lenindef)
        self.assertTrue(obj.bered)

    @given(
        integers(min_value=1).map(tag_ctxc),
        binary().filter(lambda x: not x.startswith(EOC)),
    )
    def test_ber_expl_no_eoc(self, expl, junk):
        encoded = expl + LENINDEF + Boolean(False).encode()
        with self.assertRaises(LenIndefForm):
            Boolean(expl=expl).decode(encoded + junk)
        with self.assertRaisesRegex(DecodeError, "no EOC"):
            Boolean(expl=expl).decode(encoded + junk, ctx={"bered": True})
        obj, tail = Boolean(expl=expl).decode(
            encoded + EOC + junk,
            ctx={"bered": True},
        )
        self.assertTrue(obj.expl_lenindef)
        self.assertFalse(obj.lenindef)
        self.assertFalse(obj.ber_encoded)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.expl_lenindef)
        self.assertFalse(obj.lenindef)
        self.assertFalse(obj.ber_encoded)
        self.assertTrue(obj.bered)
        self.assertSequenceEqual(tail, junk)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(
        integers(min_value=1).map(tag_ctxc),
        lists(
            booleans(),
            min_size=1,
            max_size=5,
        ),
    )
    def test_ber_expl(self, expl, values):
        encoded = b""
        for value in values:
            encoded += (
                expl +
                LENINDEF +
                Boolean(value).encode() +
                EOC
            )
        encoded = SequenceOf.tag_default + len_encode(len(encoded)) + encoded

        class SeqOf(SequenceOf):
            schema = Boolean(expl=expl)
        with self.assertRaises(LenIndefForm):
            SeqOf().decode(encoded)
        seqof, tail = SeqOf().decode(encoded, ctx={"bered": True})
        list(SeqOf().decode_evgen(encoded, ctx={"bered": True}))
        self.assertSequenceEqual(tail, b"")
        self.assertSequenceEqual([bool(v) for v in seqof], values)
        self.assertSetEqual(
            set(
                (
                    v.tlvlen,
                    v.expl_tlvlen,
                    v.expl_tlen,
                    v.expl_llen,
                    v.ber_encoded,
                    v.lenindef,
                    v.expl_lenindef,
                    v.bered,
                ) for v in seqof
            ),
            set(((
                3 + EOC_LEN,
                len(expl) + 1 + 3 + EOC_LEN,
                len(expl),
                1,
                False,
                False,
                True,
                True,
            ),)),
        )
        repr(seqof)
        list(seqof.pps())
        pprint(seqof, big_blobs=True, with_decode_path=True)


@composite
def integer_values_strategy(draw, do_expl=False):
    bound_min, value, default, bound_max = sorted(draw(sets(
        integers(),
        min_size=4,
        max_size=4,
    )))
    if draw(booleans()):
        value = None
    _specs = None
    if draw(booleans()):
        _specs = draw(sets(text_letters()))
        values = draw(sets(
            integers(),
            min_size=len(_specs),
            max_size=len(_specs),
        ))
        _specs = list(zip(_specs, values))
    bounds = None
    if draw(booleans()):
        bounds = (bound_min, bound_max)
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    if draw(booleans()):
        default = None
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, bounds, impl, expl, default, optional, _specs, _decoded)


class IntegerInherited(Integer):
    pass


class TestInteger(CommonMixin, TestCase):
    base_klass = Integer

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            Integer(12.3)
        repr(err.exception)

    @given(sets(text_letters(), min_size=2))
    def test_unknown_name(self, names_input):
        missing = names_input.pop()

        class Int(Integer):
            schema = [(n, 123) for n in names_input]
        with self.assertRaises(ObjUnknown) as err:
            Int(missing)
        repr(err.exception)

    @given(sets(text_letters(), min_size=2))
    def test_known_name(self, names_input):
        class Int(Integer):
            schema = [(n, 123) for n in names_input]
        Int(names_input.pop())

    @given(booleans())
    def test_optional(self, optional):
        obj = Integer(default=Integer(0), optional=optional)
        self.assertTrue(obj.optional)

    @given(integers())
    def test_ready(self, value):
        obj = Integer()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        repr(err.exception)
        obj = Integer(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        hash(obj)

    @given(integers(), integers(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        for klass in (Integer, IntegerInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == int(obj2), value1 == value2)
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(lists(integers()))
    def test_sorted_works(self, values):
        self.assertSequenceEqual(
            [int(v) for v in sorted(Integer(v) for v in values)],
            sorted(values),
        )

    @given(data_strategy())
    def test_named(self, d):
        names_input = list(d.draw(sets(text_letters(), min_size=1)))
        values_input = list(d.draw(sets(
            integers(),
            min_size=len(names_input),
            max_size=len(names_input),
        )))
        chosen_name = d.draw(sampled_from(names_input))
        names_input = dict(zip(names_input, values_input))

        class Int(Integer):
            schema = names_input
        _int = Int(chosen_name)
        self.assertEqual(_int.named, chosen_name)
        self.assertEqual(int(_int), names_input[chosen_name])

    @given(integers(), integers(min_value=0), integers(min_value=0))
    def test_bounds_satisfied(self, bound_min, bound_delta, value_delta):
        value = bound_min + value_delta
        bound_max = value + bound_delta
        Integer(value=value, bounds=(bound_min, bound_max))

    @given(sets(integers(), min_size=3, max_size=3))
    def test_bounds_unsatisfied(self, values):
        values = sorted(values)
        with self.assertRaises(BoundsError) as err:
            Integer(value=values[0], bounds=(values[1], values[2]))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            Integer(bounds=(values[1], values[2])).decode(
                Integer(values[0]).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            Integer(bounds=(values[1], values[2])).decode(
                encode2pass(Integer(values[0]))
            )
        with self.assertRaises(BoundsError) as err:
            Integer(value=values[2], bounds=(values[0], values[1]))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            Integer(bounds=(values[0], values[1])).decode(
                Integer(values[2]).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            Integer(bounds=(values[0], values[1])).decode(
                encode2pass(Integer(values[2]))
            )

    @given(data_strategy())
    def test_call(self, d):
        for klass in (Integer, IntegerInherited):
            (
                value_initial,
                bounds_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _specs_initial,
                _decoded_initial,
            ) = d.draw(integer_values_strategy())
            obj_initial = klass(
                value_initial,
                bounds_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial or False,
                _specs_initial,
                _decoded_initial,
            )
            (
                value,
                bounds,
                impl,
                expl,
                default,
                optional,
                _,
                _decoded,
            ) = d.draw(integer_values_strategy(do_expl=impl_initial is None))
            if (default is None) and (obj_initial.default is not None):
                bounds = None
            if (
                    (bounds is None) and
                    (value is not None) and
                    (bounds_initial is not None) and
                    not (bounds_initial[0] <= value <= bounds_initial[1])
            ):
                value = None
            if (
                    (bounds is None) and
                    (default is not None) and
                    (bounds_initial is not None) and
                    not (bounds_initial[0] <= default <= bounds_initial[1])
            ):
                default = None
            obj = obj_initial(value, bounds, impl, expl, default, optional)
            if obj.ready:
                value_expected = default if value is None else value
                value_expected = (
                    default_initial if value_expected is None
                    else value_expected
                )
                self.assertEqual(obj, value_expected)
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            self.assertEqual(
                obj.default,
                default_initial if default is None else default,
            )
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)
            self.assertEqual(
                (obj._bound_min, obj._bound_max),
                bounds or bounds_initial or (float("-inf"), float("+inf")),
            )
            self.assertEqual(
                obj.specs,
                {} if _specs_initial is None else dict(_specs_initial),
            )

    @given(integer_values_strategy())
    def test_copy(self, values):
        for klass in (Integer, IntegerInherited):
            obj = klass(*values)
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj.specs, obj_copied.specs)
                self.assertEqual(obj._bound_min, obj_copied._bound_min)
                self.assertEqual(obj._bound_max, obj_copied._bound_max)
                self.assertEqual(obj._value, obj_copied._value)

    @given(
        integers(),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, value, tag_impl):
        obj = Integer(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = Integer(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    def test_zero_len(self):
        with self.assertRaises(NotEnoughData):
            Integer().decode(b"".join((
                Integer.tag_default,
                len_encode(0),
            )))

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Integer().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Integer().decode(
                Integer.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        sets(integers(), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class Int(Integer):
            bounds = (bound_min, bound_min)
        with self.assertRaises(DecodeError) as err:
            Int().decode(
                Integer(value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        integer_values_strategy(),
        integers(),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
    )
    def test_symmetric(self, values, value, tag_expl, offset, tail_junk, decode_path):
        for klass in (Integer, IntegerInherited):
            _, _, _, _, default, optional, _, _decoded = values
            obj = klass(
                value=value,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled_encoded,
            )
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertEqual(int(obj_decoded), int(obj_expled))
            self.assertEqual(int(obj_decoded), int(obj))
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj, obj_decoded)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    def test_go_vectors_valid(self):
        for data, expect in ((
                (b"\x00", 0),
                (b"\x7f", 127),
                (b"\x80", -128),
                (b"\xff\x7f", -129),
                (b"\xff", -1),
                (b"\x01", 1),
                (b"\x00\xff", 255),
                (b"\xff\x00", -256),
                (b"\x01\x00", 256),
                (b"\x00\x80", 128),
                (b"\x01\x00", 256),
                (b"\x80\x00\x00\x00\x00\x00\x00\x00", -9223372036854775808),
                (b"\x80\x00\x00\x00", -2147483648),
        )):
            self.assertEqual(
                Integer().decode(b"".join((
                    Integer.tag_default,
                    len_encode(len(data)),
                    data,
                )))[0],
                expect,
            )

    def test_go_vectors_invalid(self):
        for data in ((
                b"\x00\x7f",
                b"\xff\xf0",
        )):
            with self.assertRaises(DecodeError):
                Integer().decode(b"".join((
                    Integer.tag_default,
                    len_encode(len(data)),
                    data,
                )))


@composite
def bit_string_values_strategy(draw, schema=None, value_required=False, do_expl=False):
    if schema is None:
        schema = ()
        if draw(booleans()):
            schema = draw(sets(text_letters(), min_size=1, max_size=256))
            bits = draw(sets(
                integers(min_value=0, max_value=255),
                min_size=len(schema),
                max_size=len(schema),
            ))
            schema = list(zip(schema, bits))

    def _value(value_required):
        if not value_required and draw(booleans()):
            return None
        generation_choice = 0
        if value_required:
            generation_choice = draw(sampled_from((1, 2, 3)))
        if generation_choice == 1 or draw(booleans()):
            return "'%s'B" % "".join(draw(lists(
                sampled_from(("0", "1")),
                max_size=len(schema),
            )))
        if generation_choice == 2 or draw(booleans()):
            return draw(binary(max_size=len(schema) // 8))
        if generation_choice == 3 or draw(booleans()):
            if len(schema) == 0:
                return ()
            return tuple(draw(lists(sampled_from([name for name, _ in schema]))))
        return None
    value = _value(value_required)
    default = _value(value_required=False)
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (schema, value, impl, expl, default, optional, _decoded)


class BitStringInherited(BitString):
    pass


class TestBitString(CommonMixin, TestCase):
    base_klass = BitString

    @given(lists(booleans()))
    def test_b_encoding(self, bits):
        obj = BitString("'%s'B" % "".join("1" if bit else "0" for bit in bits))
        self.assertEqual(obj.bit_len, len(bits))
        self.assertSequenceEqual(list(obj), bits)
        for i, bit in enumerate(bits):
            self.assertEqual(obj[i], bit)

    @given(lists(booleans()))
    def test_out_of_bounds_bits(self, bits):
        obj = BitString("'%s'B" % "".join("1" if bit else "0" for bit in bits))
        for i in range(len(bits), len(bits) * 2):
            self.assertFalse(obj[i])

    def test_bad_b_encoding(self):
        with self.assertRaises(ValueError):
            BitString("'010120101'B")

    @given(
        integers(min_value=1, max_value=255),
        integers(min_value=1, max_value=255),
    )
    def test_named_are_stripped(self, leading_zeros, trailing_zeros):
        obj = BitString("'%s1%s'B" % (("0" * leading_zeros), ("0" * trailing_zeros)))
        self.assertEqual(obj.bit_len, leading_zeros + 1 + trailing_zeros)
        self.assertGreater(len(obj.encode()), (leading_zeros + 1 + trailing_zeros) // 8)

        class BS(BitString):
            schema = (("whatever", 0),)
        obj = BS("'%s1%s'B" % (("0" * leading_zeros), ("0" * trailing_zeros)))
        self.assertEqual(obj.bit_len, leading_zeros + 1)
        self.assertGreater(len(obj.encode()), (leading_zeros + 1) // 8)

    def test_zero_len(self):
        with self.assertRaises(NotEnoughData):
            BitString().decode(b"".join((
                BitString.tag_default,
                len_encode(0),
            )))

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            BitString(123)
        repr(err.exception)
        with self.assertRaises(InvalidValueType) as err:
            BitString(u"123")
        repr(err.exception)

    def test_obj_unknown(self):
        with self.assertRaises(ObjUnknown) as err:
            BitString(b"whatever")["whenever"]
        repr(err.exception)

    def test_get_invalid_type(self):
        with self.assertRaises(InvalidValueType) as err:
            BitString(b"whatever")[(1, 2, 3)]
        repr(err.exception)

    @given(data_strategy())
    def test_unknown_name(self, d):
        _schema = d.draw(sets(text_letters(), min_size=2, max_size=5))
        missing = _schema.pop()

        class BS(BitString):
            schema = [(n, i) for i, n in enumerate(_schema)]
        with self.assertRaises(ObjUnknown) as err:
            BS((missing,))
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = BitString(default=BitString(b""), optional=optional)
        self.assertTrue(obj.optional)

    @given(binary())
    def test_ready(self, value):
        obj = BitString()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        obj = BitString(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(
        tuples(integers(min_value=0), binary()),
        tuples(integers(min_value=0), binary()),
        binary(min_size=1),
        binary(min_size=1),
    )
    def test_comparison(self, value1, value2, tag1, tag2):
        for klass in (BitString, BitStringInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == bytes(obj2), value1[1] == value2[1])
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(data_strategy())
    def test_call(self, d):
        for klass in (BitString, BitStringInherited):
            (
                schema_initial,
                value_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(bit_string_values_strategy())

            class BS(klass):
                schema = schema_initial
            obj_initial = BS(
                value=value_initial,
                impl=impl_initial,
                expl=expl_initial,
                default=default_initial,
                optional=optional_initial or False,
                _decoded=_decoded_initial,
            )
            (
                _,
                value,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(bit_string_values_strategy(
                schema=schema_initial,
                do_expl=impl_initial is None,
            ))
            obj = obj_initial(
                value=value,
                impl=impl,
                expl=expl,
                default=default,
                optional=optional,
            )
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)
            self.assertEqual(obj.specs, obj_initial.specs)

    @given(bit_string_values_strategy())
    def test_copy(self, values):
        for klass in (BitString, BitStringInherited):
            _schema, value, impl, expl, default, optional, _decoded = values

            class BS(klass):
                schema = _schema
            register_class(BS)
            obj = BS(
                value=value,
                impl=impl,
                expl=expl,
                default=default,
                optional=optional or False,
                _decoded=_decoded,
            )
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj.specs, obj_copied.specs)
                self.assertEqual(obj._value, obj_copied._value)

    @given(
        binary(),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, value, tag_impl):
        obj = BitString(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        binary(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = BitString(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            BitString().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            BitString().decode(
                BitString.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric(self, d):
        (
            _schema,
            value,
            _,
            _,
            default,
            optional,
            _decoded,
        ) = d.draw(bit_string_values_strategy(value_required=True))
        tail_junk = d.draw(binary(max_size=5))
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        offset = d.draw(integers(min_value=0))
        decode_path = d.draw(decode_path_strat)
        for klass in (BitString, BitStringInherited):
            class BS(klass):
                schema = _schema
            obj = BS(
                value=value,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled_encoded,
            )
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertEqual(bytes(obj_decoded), bytes(obj_expled))
            self.assertEqual(bytes(obj_decoded), bytes(obj))
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            if isinstance(value, tuple):
                self.assertSetEqual(set(value), set(obj_decoded.named))
                for name in value:
                    obj_decoded[name]
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @given(integers(min_value=1, max_value=255))
    def test_bad_zero_value(self, pad_size):
        with self.assertRaises(DecodeError):
            BitString().decode(b"".join((
                BitString.tag_default,
                len_encode(1),
                bytes([pad_size]),
            )))

    def test_go_vectors_invalid(self):
        for data in ((
                b"\x07\x01",
                b"\x07\x40",
                b"\x08\x00",
        )):
            with self.assertRaises(DecodeError):
                BitString().decode(b"".join((
                    BitString.tag_default,
                    len_encode(2),
                    data,
                )))

    def test_go_vectors_valid(self):
        obj, _ = BitString().decode(b"".join((
            BitString.tag_default,
            len_encode(1),
            b"\x00",
        )))
        self.assertEqual(bytes(obj), b"")
        self.assertEqual(obj.bit_len, 0)

        obj, _ = BitString().decode(b"".join((
            BitString.tag_default,
            len_encode(2),
            b"\x07\x00",
        )))
        self.assertEqual(bytes(obj), b"\x00")
        self.assertEqual(obj.bit_len, 1)

        obj = BitString((16, b"\x82\x40"))
        self.assertTrue(obj[0])
        self.assertFalse(obj[1])
        self.assertTrue(obj[6])
        self.assertTrue(obj[9])
        self.assertFalse(obj[17])

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        integers(min_value=1, max_value=30),
        lists(
            one_of(
                binary(min_size=1, max_size=5),
                lists(
                    binary(min_size=1, max_size=5),
                    min_size=1,
                    max_size=3,
                ),
            ),
            min_size=0,
            max_size=3,
        ),
        lists(booleans(), min_size=1),
        binary(),
        decode_path_strat,
    )
    def test_constructed(self, impl, chunk_inputs, chunk_last_bits, junk, decode_path):
        def chunk_constructed(contents):
            return (
                tag_encode(form=TagFormConstructed, num=3) +
                LENINDEF +
                b"".join(BitString(content).encode() for content in contents) +
                EOC
            )
        chunks = []
        chunks_len_expected = []
        payload_expected = b""
        bit_len_expected = 0
        for chunk_input in chunk_inputs:
            if isinstance(chunk_input, bytes):
                chunks.append(BitString(chunk_input).encode())
                payload_expected += chunk_input
                bit_len_expected += len(chunk_input) * 8
                chunks_len_expected.append(len(chunk_input) + 1)
            else:
                chunks.append(chunk_constructed(chunk_input))
                payload = b"".join(chunk_input)
                payload_expected += payload
                bit_len_expected += len(payload) * 8
                for c in chunk_input:
                    chunks_len_expected.append(len(c) + 1)
                chunks_len_expected.append(len(chunks[-1]) - 1 - 1)
        chunk_last = BitString("'%s'B" % "".join(
            "1" if bit else "0" for bit in chunk_last_bits
        ))
        chunks_len_expected.append(BitString().decod(chunk_last.encode()).vlen)
        payload_expected += bytes(chunk_last)
        bit_len_expected += chunk_last.bit_len
        encoded_indefinite = (
            tag_encode(form=TagFormConstructed, num=impl) +
            LENINDEF +
            b"".join(chunks) +
            chunk_last.encode() +
            EOC
        )
        encoded_definite = (
            tag_encode(form=TagFormConstructed, num=impl) +
            len_encode(len(b"".join(chunks) + chunk_last.encode())) +
            b"".join(chunks) +
            chunk_last.encode()
        )
        with self.assertRaisesRegex(DecodeError, "unallowed BER"):
            BitString(impl=tag_encode(impl)).decode(encoded_indefinite)
        for lenindef_expected, encoded in (
                (True, encoded_indefinite),
                (False, encoded_definite),
        ):
            obj, tail = BitString(impl=tag_encode(impl)).decode(
                encoded + junk,
                ctx={"bered": True},
            )
            self.assertSequenceEqual(tail, junk)
            self.assertEqual(obj.bit_len, bit_len_expected)
            self.assertSequenceEqual(bytes(obj), payload_expected)
            self.assertTrue(obj.ber_encoded)
            self.assertEqual(obj.lenindef, lenindef_expected)
            self.assertTrue(obj.bered)
            obj = copy(obj)
            self.assertTrue(obj.ber_encoded)
            self.assertEqual(obj.lenindef, lenindef_expected)
            self.assertTrue(obj.bered)
            self.assertEqual(len(encoded), obj.tlvlen)
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)

            evgens = list(BitString(impl=tag_encode(impl)).decode_evgen(
                encoded,
                decode_path=decode_path,
                ctx={"bered": True},
            ))
            self.assertEqual(len(evgens), len(chunks_len_expected) + 1)
            for chunk_len_expected, (dp, obj, _) in zip(chunks_len_expected, evgens):
                self.assertGreater(len(dp), len(decode_path))
                self.assertEqual(obj.vlen, chunk_len_expected)

    @given(
        integers(min_value=0),
        decode_path_strat,
    )
    def test_ber_definite_too_short(self, offset, decode_path):
        with self.assertRaisesRegex(DecodeError, "longer than data") as err:
            BitString().decode(
                tag_encode(3, form=TagFormConstructed) + len_encode(1),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path)
        self.assertEqual(err.exception.offset, offset)

    @given(
        integers(min_value=0),
        decode_path_strat,
    )
    def test_ber_definite_no_data(self, offset, decode_path):
        with self.assertRaisesRegex(DecodeError, "zero length") as err:
            BitString().decode(
                tag_encode(3, form=TagFormConstructed) + len_encode(0),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path)
        self.assertEqual(err.exception.offset, offset)

    @given(
        integers(min_value=0),
        decode_path_strat,
        integers(min_value=1, max_value=3),
    )
    def test_ber_indefinite_no_eoc(self, offset, decode_path, chunks):
        bs = BitString(b"data").encode()
        with self.assertRaises(NotEnoughData) as err:
            BitString().decode(
                tag_encode(3, form=TagFormConstructed) + LENINDEF + chunks * bs,
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path + (str(chunks),))
        self.assertEqual(err.exception.offset, offset + 1 + 1 + chunks * len(bs))

    @given(
        integers(min_value=0),
        decode_path_strat,
        integers(min_value=1, max_value=3),
    )
    def test_ber_definite_chunk_out_of_bounds(self, offset, decode_path, chunks):
        bs = BitString(b"data").encode()
        bs_longer = BitString(b"data-longer").encode()
        with self.assertRaisesRegex(DecodeError, "chunk out of bounds") as err:
            BitString().decode(
                (
                    tag_encode(3, form=TagFormConstructed) +
                    len_encode((chunks + 1) * len(bs)) +
                    chunks * bs +
                    bs_longer
                ),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path + (str(chunks),))
        self.assertEqual(err.exception.offset, offset + 1 + 1 + chunks * len(bs))

    @given(
        integers(min_value=0),
        decode_path_strat,
    )
    def test_ber_indefinite_no_chunks(self, offset, decode_path):
        with self.assertRaisesRegex(DecodeError, "no chunks") as err:
            BitString().decode(
                tag_encode(3, form=TagFormConstructed) + LENINDEF + EOC,
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path)
        self.assertEqual(err.exception.offset, offset)

    @given(data_strategy())
    def test_ber_indefinite_not_multiple(self, d):
        bs_short = BitString("'A'H").encode()
        bs_full = BitString("'AA'H").encode()
        chunks = [bs_full for _ in range(d.draw(integers(min_value=0, max_value=3)))]
        chunks.append(bs_short)
        d.draw(permutations(chunks))
        chunks.append(bs_short)
        offset = d.draw(integers(min_value=0))
        decode_path = d.draw(decode_path_strat)
        with self.assertRaisesRegex(DecodeError, "multiple of 8 bits") as err:
            BitString().decode(
                (
                    tag_encode(3, form=TagFormConstructed) +
                    LENINDEF +
                    b"".join(chunks) +
                    EOC
                ),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(
            err.exception.decode_path,
            decode_path + (str(chunks.index(bs_short)),),
        )
        self.assertEqual(
            err.exception.offset,
            offset + 1 + 1 + chunks.index(bs_short) * len(bs_full),
        )

    def test_x690_vector(self):
        vector = BitString("'0A3B5F291CD'H")
        obj, tail = BitString().decode(hexdec("0307040A3B5F291CD0"))
        self.assertSequenceEqual(tail, b"")
        self.assertEqual(obj, vector)
        obj, tail = BitString().decode(
            hexdec("23800303000A3B0305045F291CD00000"),
            ctx={"bered": True},
        )
        self.assertSequenceEqual(tail, b"")
        self.assertEqual(obj, vector)
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.lenindef)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.lenindef)
        self.assertTrue(obj.bered)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(integers(min_value=1000, max_value=3000))
    def test_cer(self, data_len):
        data = urandom(data_len)
        encoded = encode_cer(BitString(data))
        ctx = {"bered": True}
        self.assertSequenceEqual(bytes(BitString().decod(encoded, ctx=ctx)), data)
        evgens = list(BitString().decode_evgen(encoded, ctx=ctx))
        evgens_expected = data_len // 999
        if evgens_expected * 999 != data_len:
            evgens_expected += 1
        evgens_expected += 1
        self.assertEqual(len(evgens), evgens_expected)
        for (_, obj, _) in evgens[:-2]:
            self.assertEqual(obj.vlen, 1000)
        _, obj, _ = evgens[-2]
        self.assertEqual(obj.vlen, 1 + data_len - len(evgens[:-2]) * 999)


@composite
def octet_string_values_strategy(draw, do_expl=False):
    bound_min, bound_max = sorted(draw(sets(
        integers(min_value=0, max_value=1 << 7),
        min_size=2,
        max_size=2,
    )))
    value = draw(one_of(
        none(),
        binary(min_size=bound_min, max_size=bound_max),
    ))
    default = draw(one_of(
        none(),
        binary(min_size=bound_min, max_size=bound_max),
    ))
    bounds = None
    if draw(booleans()):
        bounds = (bound_min, bound_max)
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, bounds, impl, expl, default, optional, _decoded)


class OctetStringInherited(OctetString):
    pass


class TestOctetString(CommonMixin, TestCase):
    base_klass = OctetString

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            OctetString(str(123))
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = OctetString(default=OctetString(b""), optional=optional)
        self.assertTrue(obj.optional)

    @given(binary())
    def test_ready(self, value):
        obj = OctetString()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        obj = OctetString(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(binary(), binary(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        for klass in (OctetString, OctetStringInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == bytes(obj2), value1 == value2)
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(lists(binary()))
    def test_sorted_works(self, values):
        self.assertSequenceEqual(
            [bytes(v) for v in sorted(OctetString(v) for v in values)],
            sorted(values),
        )

    @given(data_strategy())
    def test_bounds_satisfied(self, d):
        bound_min = d.draw(integers(min_value=0, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = d.draw(binary(min_size=bound_min, max_size=bound_max))
        OctetString(value=value, bounds=(bound_min, bound_max))

    @given(data_strategy())
    def test_bounds_unsatisfied(self, d):
        bound_min = d.draw(integers(min_value=1, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = d.draw(binary(max_size=bound_min - 1))
        with self.assertRaises(BoundsError) as err:
            OctetString(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            OctetString(bounds=(bound_min, bound_max)).decode(
                OctetString(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            OctetString(bounds=(bound_min, bound_max)).decode(
                encode2pass(OctetString(value))
            )
        value = d.draw(binary(min_size=bound_max + 1))
        with self.assertRaises(BoundsError) as err:
            OctetString(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            OctetString(bounds=(bound_min, bound_max)).decode(
                OctetString(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            OctetString(bounds=(bound_min, bound_max)).decode(
                encode2pass(OctetString(value))
            )

    @given(data_strategy())
    def test_call(self, d):
        for klass in (OctetString, OctetStringInherited):
            (
                value_initial,
                bounds_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(octet_string_values_strategy())
            obj_initial = klass(
                value_initial,
                bounds_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial or False,
                _decoded_initial,
            )
            (
                value,
                bounds,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(octet_string_values_strategy(do_expl=impl_initial is None))
            if (default is None) and (obj_initial.default is not None):
                bounds = None
            if (
                    (bounds is None) and
                    (value is not None) and
                    (bounds_initial is not None) and
                    not (bounds_initial[0] <= len(value) <= bounds_initial[1])
            ):
                value = None
            if (
                    (bounds is None) and
                    (default is not None) and
                    (bounds_initial is not None) and
                    not (bounds_initial[0] <= len(default) <= bounds_initial[1])
            ):
                default = None
            obj = obj_initial(value, bounds, impl, expl, default, optional)
            if obj.ready:
                value_expected = default if value is None else value
                value_expected = (
                    default_initial if value_expected is None
                    else value_expected
                )
                self.assertEqual(obj, value_expected)
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            self.assertEqual(
                obj.default,
                default_initial if default is None else default,
            )
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)
            self.assertEqual(
                (obj._bound_min, obj._bound_max),
                bounds or bounds_initial or (0, float("+inf")),
            )

    @given(octet_string_values_strategy())
    def test_copy(self, values):
        for klass in (OctetString, OctetStringInherited):
            obj = klass(*values)
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj._bound_min, obj_copied._bound_min)
                self.assertEqual(obj._bound_max, obj_copied._bound_max)
                self.assertEqual(obj._value, obj_copied._value)

    @given(
        binary(),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, value, tag_impl):
        obj = OctetString(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        binary(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = OctetString(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            OctetString().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            OctetString().decode(
                OctetString.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        sets(integers(min_value=0, max_value=10), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class String(OctetString):
            bounds = (bound_min, bound_min)
        with self.assertRaises(DecodeError) as err:
            String().decode(
                OctetString(b"\x00" * value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        octet_string_values_strategy(),
        binary(),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
        booleans(),
    )
    def test_symmetric(
            self,
            values,
            value,
            tag_expl,
            offset,
            tail_junk,
            decode_path,
            keep_memoryview,
    ):
        for klass in (OctetString, OctetStringInherited):
            _, _, _, _, default, optional, _decoded = values
            obj = klass(
                value=value,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled_encoded,
            )
            ctx_dummy["keep_memoryview"] = keep_memoryview
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertEqual(bytes(obj_decoded), bytes(obj_expled))
            self.assertEqual(bytes(obj_decoded), bytes(obj))
            self.assertIsInstance(
                obj_decoded._value,
                memoryview if keep_memoryview else bytes,
            )
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        integers(min_value=1, max_value=30),
        lists(
            one_of(
                binary(min_size=1, max_size=5),
                lists(
                    binary(min_size=1, max_size=5),
                    min_size=1,
                    max_size=3,
                ),
            ),
            min_size=1,
            max_size=3,
        ),
        binary(),
        decode_path_strat,
    )
    def test_constructed(self, impl, chunk_inputs, junk, decode_path):
        def chunk_constructed(contents):
            return (
                tag_encode(form=TagFormConstructed, num=4) +
                LENINDEF +
                b"".join(OctetString(content).encode() for content in contents) +
                EOC
            )
        chunks = []
        chunks_len_expected = []
        payload_expected = b""
        for chunk_input in chunk_inputs:
            if isinstance(chunk_input, bytes):
                chunks.append(OctetString(chunk_input).encode())
                payload_expected += chunk_input
                chunks_len_expected.append(len(chunk_input))
            else:
                chunks.append(chunk_constructed(chunk_input))
                payload = b"".join(chunk_input)
                payload_expected += payload
                for c in chunk_input:
                    chunks_len_expected.append(len(c))
                chunks_len_expected.append(len(chunks[-1]) - 1 - 1)
        encoded_indefinite = (
            tag_encode(form=TagFormConstructed, num=impl) +
            LENINDEF +
            b"".join(chunks) +
            EOC
        )
        encoded_definite = (
            tag_encode(form=TagFormConstructed, num=impl) +
            len_encode(len(b"".join(chunks))) +
            b"".join(chunks)
        )
        with self.assertRaisesRegex(DecodeError, "unallowed BER"):
            OctetString(impl=tag_encode(impl)).decode(encoded_indefinite)
        for lenindef_expected, encoded in (
                (True, encoded_indefinite),
                (False, encoded_definite),
        ):
            obj, tail = OctetString(impl=tag_encode(impl)).decode(
                encoded + junk,
                ctx={"bered": True},
            )
            self.assertSequenceEqual(tail, junk)
            self.assertSequenceEqual(bytes(obj), payload_expected)
            self.assertTrue(obj.ber_encoded)
            self.assertEqual(obj.lenindef, lenindef_expected)
            self.assertTrue(obj.bered)
            obj = copy(obj)
            self.assertTrue(obj.ber_encoded)
            self.assertEqual(obj.lenindef, lenindef_expected)
            self.assertTrue(obj.bered)
            self.assertEqual(len(encoded), obj.tlvlen)
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)

            evgens = list(OctetString(impl=tag_encode(impl)).decode_evgen(
                encoded,
                decode_path=decode_path,
                ctx={"bered": True},
            ))
            self.assertEqual(len(evgens), len(chunks_len_expected) + 1)
            for chunk_len_expected, (dp, obj, _) in zip(chunks_len_expected, evgens):
                self.assertGreater(len(dp), len(decode_path))
                self.assertEqual(obj.vlen, chunk_len_expected)

    @given(
        integers(min_value=0),
        decode_path_strat,
    )
    def test_ber_definite_too_short(self, offset, decode_path):
        with self.assertRaisesRegex(DecodeError, "longer than data") as err:
            OctetString().decode(
                tag_encode(4, form=TagFormConstructed) + len_encode(1),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path)
        self.assertEqual(err.exception.offset, offset)

    @given(
        integers(min_value=0),
        decode_path_strat,
        integers(min_value=1, max_value=3),
    )
    def test_ber_indefinite_no_eoc(self, offset, decode_path, chunks):
        bs = OctetString(b"data").encode()
        with self.assertRaises(NotEnoughData) as err:
            OctetString().decode(
                tag_encode(4, form=TagFormConstructed) + LENINDEF + chunks * bs,
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path + (str(chunks),))
        self.assertEqual(err.exception.offset, offset + 1 + 1 + chunks * len(bs))

    @given(
        integers(min_value=0),
        decode_path_strat,
        integers(min_value=1, max_value=3),
    )
    def test_ber_definite_chunk_out_of_bounds(self, offset, decode_path, chunks):
        bs = OctetString(b"data").encode()
        bs_longer = OctetString(b"data-longer").encode()
        with self.assertRaisesRegex(DecodeError, "chunk out of bounds") as err:
            OctetString().decode(
                (
                    tag_encode(4, form=TagFormConstructed) +
                    len_encode((chunks + 1) * len(bs)) +
                    chunks * bs +
                    bs_longer
                ),
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.decode_path, decode_path + (str(chunks),))
        self.assertEqual(err.exception.offset, offset + 1 + 1 + chunks * len(bs))

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(integers(min_value=1001, max_value=3000))
    def test_cer(self, data_len):
        data = urandom(data_len)
        encoded = encode_cer(OctetString(data))
        ctx = {"bered": True}
        self.assertSequenceEqual(bytes(OctetString().decod(encoded, ctx=ctx)), data)
        evgens = list(OctetString().decode_evgen(encoded, ctx=ctx))
        evgens_expected = data_len // 1000
        if evgens_expected * 1000 != data_len:
            evgens_expected += 1
        evgens_expected += 1
        self.assertEqual(len(evgens), evgens_expected)
        for (_, obj, _) in evgens[:-2]:
            self.assertEqual(obj.vlen, 1000)
        _, obj, _ = evgens[-2]
        self.assertEqual(obj.vlen, data_len - len(evgens[:-2]) * 1000)


@composite
def null_values_strategy(draw, do_expl=False):
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (impl, expl, optional, _decoded)


class NullInherited(Null):
    pass


class TestNull(CommonMixin, TestCase):
    base_klass = Null

    def test_ready(self):
        obj = Null()
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(binary(min_size=1), binary(min_size=1))
    def test_comparison(self, tag1, tag2):
        for klass in (Null, NullInherited):
            obj1 = klass(impl=tag1)
            obj2 = klass(impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)
            self.assertNotEqual(obj1, tag2)

    @given(data_strategy())
    def test_call(self, d):
        for klass in (Null, NullInherited):
            (
                impl_initial,
                expl_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(null_values_strategy())
            obj_initial = klass(
                impl=impl_initial,
                expl=expl_initial,
                optional=optional_initial or False,
                _decoded=_decoded_initial,
            )
            (
                impl,
                expl,
                optional,
                _decoded,
            ) = d.draw(null_values_strategy(do_expl=impl_initial is None))
            obj = obj_initial(impl=impl, expl=expl, optional=optional)
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            optional = optional_initial if optional is None else optional
            optional = False if optional is None else optional
            self.assertEqual(obj.optional, optional)

    @given(null_values_strategy())
    def test_copy(self, values):
        for klass in (Null, NullInherited):
            impl, expl, optional, _decoded = values
            obj = klass(
                impl=impl,
                expl=expl,
                optional=optional or False,
                _decoded=_decoded,
            )
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)

    @given(integers(min_value=1).map(tag_encode))
    def test_stripped(self, tag_impl):
        obj = Null(impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(integers(min_value=1).map(tag_ctxc))
    def test_stripped_expl(self, tag_expl):
        obj = Null(expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Null().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Null().decode(
                Null.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(binary(min_size=1))
    def test_tag_mismatch(self, impl):
        assume(impl != Null.tag_default)
        with self.assertRaises(TagMismatch):
            Null(impl=impl).decode(Null().encode())

    @given(
        null_values_strategy(),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
    )
    def test_symmetric(self, values, tag_expl, offset, tail_junk, decode_path):
        for klass in (Null, NullInherited):
            _, _, optional, _decoded = values
            obj = klass(optional=optional, _decoded=_decoded)
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled_encoded,
            )
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj, obj_decoded)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @given(integers(min_value=1))
    def test_invalid_len(self, l):
        with self.assertRaises(InvalidLength):
            Null().decode(b"".join((
                Null.tag_default,
                len_encode(l),
            )))


@composite
def oid_strategy(draw):
    first_arc = draw(integers(min_value=0, max_value=2))
    second_arc = 0
    if first_arc in (0, 1):
        second_arc = draw(integers(min_value=0, max_value=39))
    else:
        second_arc = draw(integers(min_value=0, max_value=1 << 63))
    other_arcs = draw(lists(integers(min_value=0, max_value=1 << 63)))
    return tuple([first_arc, second_arc] + other_arcs)


@composite
def oid_values_strategy(draw, do_expl=False):
    value = draw(one_of(none(), oid_strategy()))
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = draw(one_of(none(), oid_strategy()))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, impl, expl, default, optional, _decoded)


class ObjectIdentifierInherited(ObjectIdentifier):
    pass


class TestObjectIdentifier(CommonMixin, TestCase):
    base_klass = ObjectIdentifier

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            ObjectIdentifier(123)
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = ObjectIdentifier(default=ObjectIdentifier("1.2.3"), optional=optional)
        self.assertTrue(obj.optional)

    @given(oid_strategy())
    def test_ready(self, value):
        obj = ObjectIdentifier()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        obj = ObjectIdentifier(value)
        self.assertTrue(obj.ready)
        self.assertFalse(obj.ber_encoded)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        hash(obj)

    @given(oid_strategy(), oid_strategy(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        for klass in (ObjectIdentifier, ObjectIdentifierInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == tuple(obj2), value1 == value2)
            self.assertEqual(str(obj1) == str(obj2), value1 == value2)
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(lists(oid_strategy()))
    def test_sorted_works(self, values):
        self.assertSequenceEqual(
            [tuple(v) for v in sorted(ObjectIdentifier(v) for v in values)],
            sorted(values),
        )

    @given(data_strategy())
    def test_call(self, d):
        for klass in (ObjectIdentifier, ObjectIdentifierInherited):
            (
                value_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(oid_values_strategy())
            obj_initial = klass(
                value=value_initial,
                impl=impl_initial,
                expl=expl_initial,
                default=default_initial,
                optional=optional_initial or False,
                _decoded=_decoded_initial,
            )
            (
                value,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(oid_values_strategy(do_expl=impl_initial is None))
            obj = obj_initial(
                value=value,
                impl=impl,
                expl=expl,
                default=default,
                optional=optional,
            )
            if obj.ready:
                value_expected = default if value is None else value
                value_expected = (
                    default_initial if value_expected is None
                    else value_expected
                )
                self.assertEqual(obj, value_expected)
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            self.assertEqual(
                obj.default,
                default_initial if default is None else default,
            )
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)

    @given(oid_values_strategy())
    def test_copy(self, values):
        for klass in (ObjectIdentifier, ObjectIdentifierInherited):
            (
                value,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = values
            obj = klass(
                value=value,
                impl=impl,
                expl=expl,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj._value, obj_copied._value)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        oid_strategy(),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, value, tag_impl):
        obj = ObjectIdentifier(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        oid_strategy(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = ObjectIdentifier(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            ObjectIdentifier().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            ObjectIdentifier().decode(
                ObjectIdentifier.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    def test_zero_oid(self):
        with self.assertRaises(NotEnoughData):
            ObjectIdentifier().decode(
                b"".join((ObjectIdentifier.tag_default, len_encode(0)))
            )

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(oid_strategy())
    def test_unfinished_oid(self, value):
        assume(list(value)[-1] > 255)
        obj_encoded = ObjectIdentifier(value).encode()
        obj, _ = ObjectIdentifier().decode(obj_encoded)
        data = obj_encoded[obj.tlen + obj.llen:-1]
        data = b"".join((
            ObjectIdentifier.tag_default,
            len_encode(len(data)),
            data,
        ))
        with self.assertRaisesRegex(DecodeError, "unfinished OID"):
            obj.decode(data)

    @given(integers(min_value=0, max_value=1 << 63))
    def test_invalid_short(self, value):
        with self.assertRaises(InvalidOID):
            ObjectIdentifier((value,))
        with self.assertRaises(InvalidOID):
            ObjectIdentifier("%d" % value)

    @given(
        integers(min_value=3, max_value=1 << 63),
        integers(min_value=0, max_value=1 << 63),
    )
    def test_invalid_first_arc(self, first_arc, second_arc):
        with self.assertRaises(InvalidOID):
            ObjectIdentifier((first_arc, second_arc))
        with self.assertRaises(InvalidOID):
            ObjectIdentifier("%d.%d" % (first_arc, second_arc))

    @given(
        integers(min_value=0, max_value=1),
        integers(min_value=40, max_value=1 << 63),
    )
    def test_invalid_second_arc(self, first_arc, second_arc):
        with self.assertRaises(InvalidOID):
            ObjectIdentifier((first_arc, second_arc))
        with self.assertRaises(InvalidOID):
            ObjectIdentifier("%d.%d" % (first_arc, second_arc))

    @given(text(alphabet=ascii_letters + ".", min_size=1))
    def test_junk(self, oid):
        with self.assertRaises(InvalidOID):
            ObjectIdentifier(oid)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(oid_strategy())
    def test_validness(self, oid):
        obj = ObjectIdentifier(oid)
        self.assertEqual(obj, ObjectIdentifier(".".join(str(arc) for arc in oid)))
        str(obj)
        repr(obj)
        pprint(obj, big_blobs=True, with_decode_path=True)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        oid_values_strategy(),
        oid_strategy(),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
    )
    def test_symmetric(self, values, value, tag_expl, offset, tail_junk, decode_path):
        for klass in (ObjectIdentifier, ObjectIdentifierInherited):
            _, _, _, default, optional, _decoded = values
            obj = klass(
                value=value,
                default=default,
                optional=optional,
                _decoded=_decoded,
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            self.assertSequenceEqual(encode_cer(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            obj_expled_cer = encode_cer(obj_expled)
            self.assertNotEqual(obj_expled_cer, obj_encoded)
            self.assertSequenceEqual(
                obj_expled.decod(obj_expled_cer, ctx={"bered": True}).encode(),
                obj_expled_encoded,
            )
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertNotEqual(obj_decoded, obj)
            self.assertEqual(tuple(obj_decoded), tuple(obj_expled))
            self.assertEqual(tuple(obj_decoded), tuple(obj))
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj, obj_decoded)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @given(
        oid_strategy().map(ObjectIdentifier),
        oid_strategy().map(ObjectIdentifier),
    )
    def test_add(self, oid1, oid2):
        oid_expect = ObjectIdentifier(str(oid1) + "." + str(oid2))
        for oid_to_add in (oid2, tuple(oid2)):
            self.assertEqual(oid1 + oid_to_add, oid_expect)
        with self.assertRaises(InvalidValueType):
            oid1 + str(oid2)

    def test_go_vectors_valid(self):
        for data, expect in (
                (b"\x55", (2, 5)),
                (b"\x55\x02", (2, 5, 2)),
                (b"\x55\x02\xc0\x00", (2, 5, 2, 8192)),
                (b"\x81\x34\x03", (2, 100, 3)),
        ):
            self.assertEqual(
                ObjectIdentifier().decode(b"".join((
                    ObjectIdentifier.tag_default,
                    len_encode(len(data)),
                    data,
                )))[0],
                expect,
            )

    def test_go_vectors_invalid(self):
        data = b"\x55\x02\xc0\x80\x80\x80\x80"
        with self.assertRaises(DecodeError):
            ObjectIdentifier().decode(b"".join((
                Integer.tag_default,
                len_encode(len(data)),
                data,
            )))

    def test_go_non_minimal_encoding(self):
        with self.assertRaises(DecodeError):
            ObjectIdentifier().decode(hexdec("060a2a80864886f70d01010b"))

    def test_x690_vector(self):
        self.assertEqual(
            ObjectIdentifier().decode(hexdec("0603883703"))[0],
            ObjectIdentifier((2, 999, 3)),
        )

    def test_nonnormalized_first_arc(self):
        tampered = (
            ObjectIdentifier.tag_default +
            len_encode(2) +
            b'\x80' +
            ObjectIdentifier((1, 0)).encode()[-1:]
        )
        obj, _ = ObjectIdentifier().decode(tampered, ctx={"bered": True})
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.bered)
        with self.assertRaisesRegex(DecodeError, "non normalized arc encoding"):
            ObjectIdentifier().decode(tampered)

    @given(data_strategy())
    def test_negative_arcs(self, d):
        oid = list(d.draw(oid_strategy()))
        if len(oid) == 2:
            return
        idx = d.draw(integers(min_value=3, max_value=len(oid)))
        oid[idx - 1] *= -1
        if oid[idx - 1] == 0:
            oid[idx - 1] = -1
        with self.assertRaises(InvalidOID):
            ObjectIdentifier(tuple(oid))
        with self.assertRaises(InvalidOID):
            ObjectIdentifier(".".join(str(i) for i in oid))

    @given(data_strategy())
    def test_plused_arcs(self, d):
        oid = [str(arc) for arc in d.draw(oid_strategy())]
        idx = d.draw(integers(min_value=0, max_value=len(oid)))
        oid[idx - 1] = "+" + oid[idx - 1]
        with self.assertRaises(InvalidOID):
            ObjectIdentifier(".".join(str(i) for i in oid))

    @given(data_strategy())
    def test_nonnormalized_arcs(self, d):
        arcs = d.draw(lists(
            integers(min_value=0, max_value=100),
            min_size=1,
            max_size=5,
        ))
        dered = ObjectIdentifier((1, 0) + tuple(arcs)).encode()
        _, _, lv = tag_strip(dered)
        _, _, v = len_decode(lv)
        v_no_first_arc = v[1:]
        idx_for_tamper = d.draw(integers(
            min_value=0,
            max_value=len(v_no_first_arc) - 1,
        ))
        tampered = list(bytearray(v_no_first_arc))
        for _ in range(d.draw(integers(min_value=1, max_value=3))):
            tampered.insert(idx_for_tamper, 0x80)
        tampered = bytes(bytearray(tampered))
        tampered = (
            ObjectIdentifier.tag_default +
            len_encode(len(tampered)) +
            tampered
        )
        obj, _ = ObjectIdentifier().decode(tampered, ctx={"bered": True})
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.bered)
        with self.assertRaisesRegex(DecodeError, "non normalized arc encoding"):
            ObjectIdentifier().decode(tampered)


@composite
def enumerated_values_strategy(draw, schema=None, do_expl=False):
    if schema is None:
        schema = list(draw(sets(text_printable, min_size=1, max_size=3)))
        values = list(draw(sets(
            integers(),
            min_size=len(schema),
            max_size=len(schema),
        )))
        schema = list(zip(schema, values))
    value = draw(one_of(none(), sampled_from([k for k, v in schema])))
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = draw(one_of(none(), sampled_from([v for k, v in schema])))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (schema, value, impl, expl, default, optional, _decoded)


class TestEnumerated(CommonMixin, TestCase):
    class EWhatever(Enumerated):
        schema = (("whatever", 0),)

    base_klass = EWhatever

    def test_schema_required(self):
        with self.assertRaisesRegex(ValueError, "schema must be specified"):
            Enumerated()

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass((1, 2))
        repr(err.exception)

    @given(sets(text_letters(), min_size=2))
    def test_unknown_name(self, schema_input):
        missing = schema_input.pop()

        class E(Enumerated):
            schema = [(n, 123) for n in schema_input]
        with self.assertRaises(ObjUnknown) as err:
            E(missing)
        repr(err.exception)

    @given(
        sets(text_letters(), min_size=2),
        sets(integers(), min_size=2),
    )
    def test_unknown_value(self, schema_input, values_input):
        schema_input.pop()
        missing_value = values_input.pop()
        _input = list(zip(schema_input, values_input))

        class E(Enumerated):
            schema = _input
        with self.assertRaises(DecodeError) as err:
            E(missing_value)
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = self.base_klass(default="whatever", optional=optional)
        self.assertTrue(obj.optional)

    def test_ready(self):
        obj = self.base_klass()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        obj = self.base_klass("whatever")
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(integers(), integers(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        class E(Enumerated):
            schema = (
                ("whatever0", value1),
                ("whatever1", value2),
            )

        class EInherited(E):
            pass
        for klass in (E, EInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == int(obj2), value1 == value2)
            obj1 = klass(value1, impl=tag1)
            obj2 = klass(value1, impl=tag2)
            self.assertEqual(obj1 == obj2, tag1 == tag2)
            self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(data_strategy())
    def test_call(self, d):
        (
            schema_initial,
            value_initial,
            impl_initial,
            expl_initial,
            default_initial,
            optional_initial,
            _decoded_initial,
        ) = d.draw(enumerated_values_strategy())

        class E(Enumerated):
            schema = schema_initial
        obj_initial = E(
            value=value_initial,
            impl=impl_initial,
            expl=expl_initial,
            default=default_initial,
            optional=optional_initial or False,
            _decoded=_decoded_initial,
        )
        (
            _,
            value,
            impl,
            expl,
            default,
            optional,
            _decoded,
        ) = d.draw(enumerated_values_strategy(
            schema=schema_initial,
            do_expl=impl_initial is None,
        ))
        obj = obj_initial(
            value=value,
            impl=impl,
            expl=expl,
            default=default,
            optional=optional,
        )
        if obj.ready:
            value_expected = default if value is None else value
            value_expected = (
                default_initial if value_expected is None
                else value_expected
            )
            self.assertEqual(
                int(obj),
                dict(schema_initial).get(value_expected, value_expected),
            )
        self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
        self.assertEqual(obj.expl_tag, expl or expl_initial)
        self.assertEqual(
            obj.default,
            default_initial if default is None else default,
        )
        if obj.default is None:
            optional = optional_initial if optional is None else optional
            optional = False if optional is None else optional
        else:
            optional = True
        self.assertEqual(obj.optional, optional)
        self.assertEqual(obj.specs, dict(schema_initial))

    @given(enumerated_values_strategy())
    def test_copy(self, values):
        schema_input, value, impl, expl, default, optional, _decoded = values

        class E(Enumerated):
            schema = schema_input
        register_class(E)
        obj = E(
            value=value,
            impl=impl,
            expl=expl,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        for copy_func in copy_funcs:
            obj_copied = copy_func(obj)
            self.assert_copied_basic_fields(obj, obj_copied)
            self.assertEqual(obj.specs, obj_copied.specs)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric(self, d):
        schema_input, _, _, _, default, optional, _decoded = d.draw(
            enumerated_values_strategy(),
        )
        tag_expl = d.draw(integers(min_value=1).map(tag_ctxc))
        offset = d.draw(integers(min_value=0))
        value = d.draw(sampled_from(sorted([v for _, v in schema_input])))
        tail_junk = d.draw(binary(max_size=5))
        decode_path = d.draw(decode_path_strat)

        class E(Enumerated):
            schema = schema_input
        obj = E(
            value=value,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertFalse(obj.expled)
        obj_encoded = obj.encode()
        self.assertEqual(encode2pass(obj), obj_encoded)
        obj_expled = obj(value, expl=tag_expl)
        self.assertTrue(obj_expled.expled)
        repr(obj_expled)
        list(obj_expled.pps())
        pprint(obj_expled, big_blobs=True, with_decode_path=True)
        obj_expled_encoded = obj_expled.encode()
        ctx_copied = deepcopy(ctx_dummy)
        obj_decoded, tail = obj_expled.decode(
            obj_expled_encoded + tail_junk,
            offset=offset,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        repr(obj_decoded)
        list(obj_decoded.pps())
        pprint(obj_decoded, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail, tail_junk)
        self.assertEqual(obj_decoded, obj_expled)
        self.assertNotEqual(obj_decoded, obj)
        self.assertEqual(int(obj_decoded), int(obj_expled))
        self.assertEqual(int(obj_decoded), int(obj))
        self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
        self.assertEqual(obj_decoded.expl_tag, tag_expl)
        self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
        self.assertEqual(
            obj_decoded.expl_llen,
            len(len_encode(len(obj_encoded))),
        )
        self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
        self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
        self.assertEqual(
            obj_decoded.offset,
            offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
        )
        self.assertEqual(obj_decoded.expl_offset, offset)
        assert_exceeding_data(
            self,
            lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
            tail_junk,
        )

        evgens = list(obj_expled.decode_evgen(
            obj_expled_encoded + tail_junk,
            offset=offset,
            decode_path=decode_path,
            ctx=ctx_copied,
        ))
        self.assertEqual(len(evgens), 1)
        _decode_path, obj, tail = evgens[0]
        self.assertSequenceEqual(tail, tail_junk)
        self.assertEqual(_decode_path, decode_path)
        self.assertEqual(obj, obj_decoded)
        self.assertEqual(obj.expl_offset, offset)
        repr(obj)
        list(obj.pps())


@composite
def string_values_strategy(draw, alphabet, do_expl=False):
    bound_min, bound_max = sorted(draw(sets(
        integers(min_value=0, max_value=1 << 7),
        min_size=2,
        max_size=2,
    )))
    value = draw(one_of(
        none(),
        text(alphabet=alphabet, min_size=bound_min, max_size=bound_max),
    ))
    default = draw(one_of(
        none(),
        text(alphabet=alphabet, min_size=bound_min, max_size=bound_max),
    ))
    bounds = None
    if draw(booleans()):
        bounds = (bound_min, bound_max)
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, bounds, impl, expl, default, optional, _decoded)


class StringMixin(object):
    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass((1, 2))
        repr(err.exception)

    def text_alphabet(self):
        return "".join(chr(c) for c in range(256))

    @given(booleans())
    def test_optional(self, optional):
        obj = self.base_klass(default=self.base_klass(""), optional=optional)
        self.assertTrue(obj.optional)

    @given(data_strategy())
    def test_ready(self, d):
        obj = self.base_klass()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        str(obj)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        value = d.draw(text(alphabet=self.text_alphabet()))
        obj = self.base_klass(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        str(obj)

    @given(data_strategy())
    def test_comparison(self, d):
        value1 = d.draw(text(alphabet=self.text_alphabet()))
        value2 = d.draw(text(alphabet=self.text_alphabet()))
        tag1 = d.draw(binary(min_size=1))
        tag2 = d.draw(binary(min_size=1))
        obj1 = self.base_klass(value1)
        obj2 = self.base_klass(value2)
        self.assertEqual(obj1 == obj2, value1 == value2)
        self.assertEqual(obj1 != obj2, value1 != value2)
        self.assertEqual(obj1 == bytes(obj2), value1 == value2)
        self.assertEqual(obj1 == str(obj2), value1 == value2)
        obj1 = self.base_klass(value1, impl=tag1)
        obj2 = self.base_klass(value1, impl=tag2)
        self.assertEqual(obj1 == obj2, tag1 == tag2)
        self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(data_strategy())
    def test_bounds_satisfied(self, d):
        bound_min = d.draw(integers(min_value=0, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = d.draw(text(
            alphabet=self.text_alphabet(),
            min_size=bound_min,
            max_size=bound_max,
        ))
        self.base_klass(value=value, bounds=(bound_min, bound_max))

    @given(data_strategy())
    def test_bounds_unsatisfied(self, d):
        bound_min = d.draw(integers(min_value=1, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = d.draw(text(alphabet=self.text_alphabet(), max_size=bound_min - 1))
        with self.assertRaises(BoundsError) as err:
            self.base_klass(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            self.base_klass(bounds=(bound_min, bound_max)).decode(
                self.base_klass(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            self.base_klass(bounds=(bound_min, bound_max)).decode(
                encode2pass(self.base_klass(value))
            )
        value = d.draw(text(alphabet=self.text_alphabet(), min_size=bound_max + 1))
        with self.assertRaises(BoundsError) as err:
            self.base_klass(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            self.base_klass(bounds=(bound_min, bound_max)).decode(
                self.base_klass(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            self.base_klass(bounds=(bound_min, bound_max)).decode(
                encode2pass(self.base_klass(value))
            )

    @given(data_strategy())
    def test_call(self, d):
        (
            value_initial,
            bounds_initial,
            impl_initial,
            expl_initial,
            default_initial,
            optional_initial,
            _decoded_initial,
        ) = d.draw(string_values_strategy(self.text_alphabet()))
        obj_initial = self.base_klass(
            value_initial,
            bounds_initial,
            impl_initial,
            expl_initial,
            default_initial,
            optional_initial or False,
            _decoded_initial,
        )
        (
            value,
            bounds,
            impl,
            expl,
            default,
            optional,
            _decoded,
        ) = d.draw(string_values_strategy(
            self.text_alphabet(),
            do_expl=impl_initial is None,
        ))
        if (default is None) and (obj_initial.default is not None):
            bounds = None
        if (
                (bounds is None) and
                (value is not None) and
                (bounds_initial is not None) and
                not (bounds_initial[0] <= len(value) <= bounds_initial[1])
        ):
            value = None
        if (
                (bounds is None) and
                (default is not None) and
                (bounds_initial is not None) and
                not (bounds_initial[0] <= len(default) <= bounds_initial[1])
        ):
            default = None
        obj = obj_initial(value, bounds, impl, expl, default, optional)
        if obj.ready:
            value_expected = default if value is None else value
            value_expected = (
                default_initial if value_expected is None
                else value_expected
            )
            self.assertEqual(obj, value_expected)
        self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
        self.assertEqual(obj.expl_tag, expl or expl_initial)
        self.assertEqual(
            obj.default,
            default_initial if default is None else default,
        )
        if obj.default is None:
            optional = optional_initial if optional is None else optional
            optional = False if optional is None else optional
        else:
            optional = True
        self.assertEqual(obj.optional, optional)
        self.assertEqual(
            (obj._bound_min, obj._bound_max),
            bounds or bounds_initial or (0, float("+inf")),
        )

    @given(data_strategy())
    def test_copy(self, d):
        values = d.draw(string_values_strategy(self.text_alphabet()))
        obj = self.base_klass(*values)
        for copy_func in copy_funcs:
            obj_copied = copy_func(obj)
            self.assert_copied_basic_fields(obj, obj_copied)
            self.assertEqual(obj._bound_min, obj_copied._bound_min)
            self.assertEqual(obj._bound_max, obj_copied._bound_max)
            self.assertEqual(obj._value, obj_copied._value)

    @given(data_strategy())
    def test_stripped(self, d):
        value = d.draw(text(alphabet=self.text_alphabet()))
        tag_impl = tag_encode(d.draw(integers(min_value=1)))
        obj = self.base_klass(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(data_strategy())
    def test_stripped_expl(self, d):
        value = d.draw(text(alphabet=self.text_alphabet()))
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        obj = self.base_klass(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                self.base_klass.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        sets(integers(min_value=0, max_value=10), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class String(self.base_klass):
            # Multiply this value by four, to satisfy UTF-32 bounds
            # (4 bytes per character) validation
            bounds = (bound_min * 4, bound_min * 4)
        with self.assertRaises(DecodeError) as err:
            String().decode(
                self.base_klass(b"\x00\x00\x00\x00" * value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(data_strategy())
    def test_symmetric(self, d):
        values = d.draw(string_values_strategy(self.text_alphabet()))
        value = d.draw(text(alphabet=self.text_alphabet()))
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        offset = d.draw(integers(min_value=0))
        tail_junk = d.draw(binary(max_size=5))
        decode_path = d.draw(decode_path_strat)
        _, _, _, _, default, optional, _decoded = values
        obj = self.base_klass(
            value=value,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertFalse(obj.expled)
        obj_encoded = obj.encode()
        self.assertEqual(encode2pass(obj), obj_encoded)
        obj_expled = obj(value, expl=tag_expl)
        self.assertTrue(obj_expled.expled)
        repr(obj_expled)
        list(obj_expled.pps())
        pprint(obj_expled, big_blobs=True, with_decode_path=True)
        obj_expled_encoded = obj_expled.encode()
        ctx_copied = deepcopy(ctx_dummy)
        obj_decoded, tail = obj_expled.decode(
            obj_expled_encoded + tail_junk,
            offset=offset,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        repr(obj_decoded)
        list(obj_decoded.pps())
        pprint(obj_decoded, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail, tail_junk)
        self.assertEqual(obj_decoded, obj_expled)
        self.assertNotEqual(obj_decoded, obj)
        self.assertEqual(bytes(obj_decoded), bytes(obj_expled))
        self.assertEqual(bytes(obj_decoded), bytes(obj))
        self.assertEqual(str(obj_decoded), str(obj_expled))
        self.assertEqual(str(obj_decoded), str(obj))
        self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
        self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
        self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
        self.assertEqual(
            obj_decoded.expl_llen,
            len(len_encode(len(obj_encoded))),
        )
        self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
        self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
        self.assertEqual(
            obj_decoded.offset,
            offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
        )
        self.assertEqual(obj_decoded.expl_offset, offset)
        assert_exceeding_data(
            self,
            lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
            tail_junk,
        )

        evgens = list(obj_expled.decode_evgen(
            obj_expled_encoded + tail_junk,
            offset=offset,
            decode_path=decode_path,
            ctx=ctx_copied,
        ))
        self.assertEqual(len(evgens), 1)
        _decode_path, obj, tail = evgens[0]
        self.assertSequenceEqual(tail, tail_junk)
        self.assertEqual(_decode_path, decode_path)
        if not getattr(self, "evgen_mode_skip_value", True):
            self.assertEqual(obj, obj_decoded)
        self.assertEqual(obj.expl_offset, offset)
        repr(obj)
        list(obj.pps())


cyrillic_letters = text(
    alphabet="".join(chr(i) for i in list(range(0x0410, 0x044f + 1))),
    min_size=1,
    max_size=5,
)


class TestUTF8String(StringMixin, CommonMixin, TestCase):
    base_klass = UTF8String

    @given(cyrillic_letters)
    def test_byte_per_primitive(self, chars):
        char = chars[0]
        char_raw = char.encode("utf-8")
        encoded = b"".join((
            self.base_klass().tag_constructed,
            LENINDEF,
            OctetString(char_raw[:1]).encode(),
            OctetString(char_raw[1:2]).encode(),
            EOC,
        ))
        self.assertEqual(
            self.base_klass().decod(encoded, ctx={"bered": True}),
            char,
        )


class UnicodeDecodeErrorMixin(object):
    @given(cyrillic_letters)
    def test_unicode_decode_error(self, cyrillic_text):
        with self.assertRaises(DecodeError):
            self.base_klass(cyrillic_text)


class TestNumericString(StringMixin, CommonMixin, TestCase):
    base_klass = NumericString

    def text_alphabet(self):
        return digits + " "

    @given(text(alphabet=ascii_letters, min_size=1, max_size=5))
    def test_non_numeric(self, non_numeric_text):
        with self.assertRaisesRegex(DecodeError, "alphabet value"):
            self.base_klass(non_numeric_text)

    @given(
        sets(integers(min_value=0, max_value=10), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class String(self.base_klass):
            bounds = (bound_min, bound_min)
        with self.assertRaises(DecodeError) as err:
            String().decode(
                self.base_klass(b"1" * value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    def test_byte_per_primitive(self):
        encoded = b"".join((
            self.base_klass().tag_constructed,
            LENINDEF,
            OctetString(b"1").encode(),
            OctetString(b"2").encode(),
            EOC,
        ))
        self.assertEqual(
            self.base_klass().decod(encoded, ctx={"bered": True}),
            "12",
        )


class TestPrintableString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = PrintableString

    def text_alphabet(self):
        return ascii_letters + digits + " '()+,-./:=?"

    @given(text(alphabet=sorted(set(whitespace) - set(" ")), min_size=1, max_size=5))
    def test_non_printable(self, non_printable_text):
        with self.assertRaisesRegex(DecodeError, "alphabet value"):
            self.base_klass(non_printable_text)

    @given(
        sets(integers(min_value=0, max_value=10), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class String(self.base_klass):
            bounds = (bound_min, bound_min)
        with self.assertRaises(DecodeError) as err:
            String().decode(
                self.base_klass(b"1" * value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    def test_allowable_invalid_chars(self):
        for c, kwargs in (
                ("*", {"allow_asterisk": True}),
                ("&", {"allow_ampersand": True}),
                ("&*", {"allow_asterisk": True, "allow_ampersand": True}),
        ):
            s = "hello invalid"
            obj = self.base_klass(s)
            for prop in kwargs.keys():
                self.assertFalse(getattr(obj, prop))
            s += c
            with self.assertRaisesRegex(DecodeError, "alphabet value"):
                self.base_klass(s)
            self.base_klass(s, **kwargs)
            klass = self.base_klass(**kwargs)
            obj = klass(s)
            for prop in kwargs.keys():
                self.assertTrue(getattr(obj, prop))
            obj = copy(obj)
            obj(s)
            for prop in kwargs.keys():
                self.assertTrue(getattr(obj, prop))


class TestTeletexString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = TeletexString


class TestVideotexString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = VideotexString


class TestIA5String(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = IA5String

    def text_alphabet(self):
        return "".join(chr(c) for c in range(128))

    @given(integers(min_value=128, max_value=255))
    def test_alphabet_bad(self, code):
        with self.assertRaises(DecodeError):
            self.base_klass().decod(
                self.base_klass.tag_default +
                len_encode(1) +
                bytes(bytearray([code])),
            )


class TestGraphicString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = GraphicString


class TestVisibleString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = VisibleString

    def text_alphabet(self):
        return " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

    def test_x690_vector(self):
        obj, tail = VisibleString().decode(hexdec("1A054A6F6E6573"))
        self.assertSequenceEqual(tail, b"")
        self.assertEqual(str(obj), "Jones")
        self.assertFalse(obj.ber_encoded)
        self.assertFalse(obj.lenindef)
        self.assertFalse(obj.bered)

        obj, tail = VisibleString().decode(
            hexdec("3A0904034A6F6E04026573"),
            ctx={"bered": True},
        )
        self.assertSequenceEqual(tail, b"")
        self.assertEqual(str(obj), "Jones")
        self.assertTrue(obj.ber_encoded)
        self.assertFalse(obj.lenindef)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertFalse(obj.lenindef)
        self.assertTrue(obj.bered)

        obj, tail = VisibleString().decode(
            hexdec("3A8004034A6F6E040265730000"),
            ctx={"bered": True},
        )
        self.assertSequenceEqual(tail, b"")
        self.assertEqual(str(obj), "Jones")
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.lenindef)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.ber_encoded)
        self.assertTrue(obj.lenindef)
        self.assertTrue(obj.bered)

    @given(one_of((
        integers(min_value=0, max_value=ord(" ") - 1),
        integers(min_value=ord("~") + 1, max_value=255),
    )))
    def test_alphabet_bad(self, code):
        with self.assertRaises(DecodeError):
            self.base_klass().decod(
                self.base_klass.tag_default +
                len_encode(1) +
                bytes(bytearray([code])),
            )

    @given(
        sets(integers(min_value=0, max_value=10), min_size=2, max_size=2),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_invalid_bounds_while_decoding(self, ints, offset, decode_path):
        value, bound_min = list(sorted(ints))

        class String(self.base_klass):
            bounds = (bound_min, bound_min)
        with self.assertRaises(DecodeError) as err:
            String().decode(
                self.base_klass(b"1" * value).encode(),
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)


class TestGeneralString(
        UnicodeDecodeErrorMixin,
        StringMixin,
        CommonMixin,
        TestCase,
):
    base_klass = GeneralString


class TestUniversalString(StringMixin, CommonMixin, TestCase):
    base_klass = UniversalString


class TestBMPString(StringMixin, CommonMixin, TestCase):
    base_klass = BMPString


@composite
def generalized_time_values_strategy(
        draw,
        min_datetime,
        max_datetime,
        omit_ms=False,
        do_expl=False,
):
    value = None
    if draw(booleans()):
        value = draw(datetimes(min_value=min_datetime, max_value=max_datetime))
        if omit_ms:
            value = value.replace(microsecond=0)
    default = None
    if draw(booleans()):
        default = draw(datetimes(min_value=min_datetime, max_value=max_datetime))
        if omit_ms:
            default = default.replace(microsecond=0)
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, impl, expl, default, optional, _decoded)


class TimeMixin(object):
    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass(datetime.now().timetuple())
        repr(err.exception)

    @given(data_strategy())
    def test_optional(self, d):
        default = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        optional = d.draw(booleans())
        obj = self.base_klass(default=default, optional=optional)
        self.assertTrue(obj.optional)

    @given(data_strategy())
    def test_ready(self, d):
        obj = self.base_klass()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        value = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        obj = self.base_klass(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(data_strategy())
    def test_comparison(self, d):
        value1 = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        value2 = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        tag1 = d.draw(binary(min_size=1))
        tag2 = d.draw(binary(min_size=1))
        if self.omit_ms:
            value1 = value1.replace(microsecond=0)
            value2 = value2.replace(microsecond=0)
        obj1 = self.base_klass(value1)
        obj2 = self.base_klass(value2)
        self.assertEqual(obj1 == obj2, value1 == value2)
        self.assertEqual(obj1 != obj2, value1 != value2)
        self.assertEqual(obj1 == obj2.todatetime(), value1 == value2)
        self.assertEqual(obj1 == bytes(obj2), value1 == value2)
        obj1 = self.base_klass(value1, impl=tag1)
        obj2 = self.base_klass(value1, impl=tag2)
        self.assertEqual(obj1 == obj2, tag1 == tag2)
        self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(data_strategy())
    def test_call(self, d):
        (
            value_initial,
            impl_initial,
            expl_initial,
            default_initial,
            optional_initial,
            _decoded_initial,
        ) = d.draw(generalized_time_values_strategy(
            min_datetime=self.min_datetime,
            max_datetime=self.max_datetime,
            omit_ms=self.omit_ms,
        ))
        obj_initial = self.base_klass(
            value=value_initial,
            impl=impl_initial,
            expl=expl_initial,
            default=default_initial,
            optional=optional_initial or False,
            _decoded=_decoded_initial,
        )
        (
            value,
            impl,
            expl,
            default,
            optional,
            _decoded,
        ) = d.draw(generalized_time_values_strategy(
            min_datetime=self.min_datetime,
            max_datetime=self.max_datetime,
            omit_ms=self.omit_ms,
            do_expl=impl_initial is None,
        ))
        obj = obj_initial(
            value=value,
            impl=impl,
            expl=expl,
            default=default,
            optional=optional,
        )
        if obj.ready:
            value_expected = default if value is None else value
            value_expected = (
                default_initial if value_expected is None
                else value_expected
            )
            self.assertEqual(obj, value_expected)
        self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
        self.assertEqual(obj.expl_tag, expl or expl_initial)
        self.assertEqual(
            obj.default,
            default_initial if default is None else default,
        )
        if obj.default is None:
            optional = optional_initial if optional is None else optional
            optional = False if optional is None else optional
        else:
            optional = True
        self.assertEqual(obj.optional, optional)

    @given(data_strategy())
    def test_copy(self, d):
        values = d.draw(generalized_time_values_strategy(
            min_datetime=self.min_datetime,
            max_datetime=self.max_datetime,
        ))
        obj = self.base_klass(*values)
        for copy_func in copy_funcs:
            obj_copied = copy_func(obj)
            self.assert_copied_basic_fields(obj, obj_copied)
            self.assertEqual(obj._value, obj_copied._value)

    @given(data_strategy())
    def test_stripped(self, d):
        value = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        tag_impl = tag_encode(d.draw(integers(min_value=1)))
        obj = self.base_klass(value, impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(data_strategy())
    def test_stripped_expl(self, d):
        value = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        obj = self.base_klass(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric(self, d):
        values = d.draw(generalized_time_values_strategy(
            min_datetime=self.min_datetime,
            max_datetime=self.max_datetime,
        ))
        value = d.draw(datetimes(
            min_value=self.min_datetime,
            max_value=self.max_datetime,
        ))
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        offset = d.draw(integers(min_value=0))
        tail_junk = d.draw(binary(max_size=5))
        _, _, _, default, optional, _decoded = values
        obj = self.base_klass(
            value=value,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertFalse(obj.expled)
        obj_encoded = obj.encode()
        self.assertEqual(encode2pass(obj), obj_encoded)
        self.additional_symmetric_check(value, obj_encoded)
        obj_expled = obj(value, expl=tag_expl)
        self.assertTrue(obj_expled.expled)
        repr(obj_expled)
        list(obj_expled.pps())
        pprint(obj_expled, big_blobs=True, with_decode_path=True)
        obj_expled_encoded = obj_expled.encode()
        ctx_copied = deepcopy(ctx_dummy)
        obj_decoded, tail = obj_expled.decode(
            obj_expled_encoded + tail_junk,
            offset=offset,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        repr(obj_decoded)
        list(obj_decoded.pps())
        pprint(obj_decoded, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail, tail_junk)
        self.assertEqual(obj_decoded, obj_expled)
        self.assertEqual(obj_decoded.todatetime(), obj_expled.todatetime())
        self.assertEqual(obj_decoded.todatetime(), obj.todatetime())
        self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
        self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
        self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
        self.assertEqual(
            obj_decoded.expl_llen,
            len(len_encode(len(obj_encoded))),
        )
        self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
        self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
        self.assertEqual(
            obj_decoded.offset,
            offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
        )
        self.assertEqual(obj_decoded.expl_offset, offset)
        assert_exceeding_data(
            self,
            lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
            tail_junk,
        )


class TestGeneralizedTime(TimeMixin, CommonMixin, TestCase):
    base_klass = GeneralizedTime
    omit_ms = False
    min_datetime = datetime(1900, 1, 1)
    max_datetime = datetime(9999, 12, 31)
    evgen_mode_skip_value = False

    def additional_symmetric_check(self, value, obj_encoded):
        if value.microsecond > 0:
            self.assertFalse(obj_encoded.endswith(b"0Z"))

    def test_repr_not_ready(self):
        str(GeneralizedTime())
        repr(GeneralizedTime())

    def test_x690_vector_valid(self):
        for data in ((
                b"19920521000000Z",
                b"19920622123421Z",
                b"19920722132100.3Z",
        )):
            GeneralizedTime(data)

    def test_x690_vector_invalid(self):
        for data in ((
                b"19920520240000Z",
                b"19920622123421.0Z",
                b"19920722132100.30Z",
        )):
            with self.assertRaises(DecodeError) as err:
                GeneralizedTime(data)
            repr(err.exception)

    def test_go_vectors_invalid(self):
        for data in ((
                b"20100102030405",
                b"00000100000000Z",
                b"20101302030405Z",
                b"20100002030405Z",
                b"20100100030405Z",
                b"20100132030405Z",
                b"20100231030405Z",
                b"20100102240405Z",
                b"20100102036005Z",
                b"20100102030460Z",
                b"-20100102030410Z",
                b"2010-0102030410Z",
                b"2010-0002030410Z",
                b"201001-02030410Z",
                b"20100102-030410Z",
                b"2010010203-0410Z",
                b"201001020304-10Z",
                # These ones are INVALID in *DER*, but accepted
                # by Go's encoding/asn1
                b"20100102030405+0607",
                b"20100102030405-0607",
        )):
            with self.assertRaises(DecodeError) as err:
                GeneralizedTime(data)
            repr(err.exception)

    def test_go_vectors_valid(self):
        self.assertEqual(
            GeneralizedTime(b"20100102030405Z").todatetime(),
            datetime(2010, 1, 2, 3, 4, 5, 0),
        )

    def test_go_vectors_valid_ber(self):
        for data in ((
                b"20100102030405+0607",
                b"20100102030405-0607",
        )):
            GeneralizedTime(data, ctx={"bered": True})

    def test_utc_offsets(self):
        """Some know equal UTC offsets
        """
        dts = [
            GeneralizedTime(data.encode("ascii"), ctx={"bered": True})
            for data in (
                "200101011830Z",
                "200101012230+04",
                "200101011130-0700",
                "200101011500-03:30",
            )
        ]
        self.assertEqual(dts[0], dts[1])
        self.assertEqual(dts[0], dts[2])
        self.assertEqual(dts[0], dts[3])

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_valid_ber(self, d):
        year = d.draw(integers(min_value=2, max_value=9999))
        month = d.draw(integers(min_value=1, max_value=12))
        day = d.draw(integers(min_value=1, max_value=28))
        hours = d.draw(integers(min_value=0, max_value=23))
        data = "%04d%02d%02d%02d" % (year, month, day, hours)
        dt = datetime(year, month, day, hours)
        fractions_sign = d.draw(sampled_from("  ,."))
        fractions = None
        if fractions_sign != " ":
            fractions = random()
        if d.draw(booleans()):
            minutes = d.draw(integers(min_value=0, max_value=59))
            data += "%02d" % minutes
            dt += timedelta(seconds=60 * minutes)
            if d.draw(booleans()):
                seconds = d.draw(integers(min_value=0, max_value=59))
                data += "%02d" % seconds
                dt += timedelta(seconds=seconds)
                if fractions is not None:
                    dt += timedelta(microseconds=10**6 * fractions)
            elif fractions is not None:
                dt += timedelta(seconds=60 * fractions)
        elif fractions is not None:
            dt += timedelta(seconds=3600 * fractions)
        if fractions is not None:
            data += fractions_sign + str(fractions)[2:]
        if d.draw(booleans()):
            data += "Z"
        elif d.draw(booleans()):
            offset_hour = d.draw(integers(min_value=0, max_value=13))
            sign = 1
            if d.draw(booleans()):
                data += "-"
                sign = -1
            else:
                data += "+"
            dt -= timedelta(seconds=sign * 3600 * offset_hour)
            data += "%02d" % offset_hour
            minutes_separator = d.draw(sampled_from((None, "", ":")))
            if minutes_separator is not None:
                offset_minute = d.draw(integers(min_value=0, max_value=59))
                dt -= timedelta(seconds=sign * 60 * offset_minute)
                data += "%s%02d" % (minutes_separator, offset_minute)
        data = data.encode("ascii")
        data_der = GeneralizedTime.tag_default + len_encode(len(data)) + data
        try:
            GeneralizedTime().decod(data_der)
        except DecodeError:
            dered = False
        else:
            dered = True
        obj = GeneralizedTime().decod(data_der, ctx={"bered": True})
        if dt.year > 1970:
            self.assertEqual(
                mktime(obj.todatetime().timetuple()),
                mktime(dt.timetuple()),
            )
        else:
            try:
                obj.todatetime().timestamp()
            except:
                pass
            else:
                self.assertEqual(obj.todatetime().timestamp(), dt.timestamp())
        self.assertEqual(obj.ber_encoded, not dered)
        self.assertEqual(obj.bered, not dered)
        self.assertEqual(obj.ber_raw, None if dered else data)
        self.assertEqual(obj.encode() == data_der, dered)
        repr(obj)
        bytes(obj)
        str(obj)

    def test_invalid_ber(self):
        for data in ((
                # "00010203040506.07",
                "-0010203040506.07",
                "0001-203040506.07",
                "000102-3040506.07",
                "00010203-40506.07",
                "0001020304-506.07",
                "000102030405-6.07",
                "00010203040506.-7",
                "+0010203040506.07",
                "0001+203040506.07",
                "000102+3040506.07",
                "00010203+40506.07",
                "0001020304+506.07",
                "000102030405+6.07",
                "00010203040506.+7",
                " 0010203040506.07",
                "0001 203040506.07",
                "000102 3040506.07",
                "00010203 40506.07",
                "0001020304 506.07",
                "000102030405 6.07",
                "00010203040506. 7",
                "001 0203040506.07",
                "00012 03040506.07",
                "0001023 040506.07",
                "000102034 0506.07",
                "00010203045 06.07",
                "0001020304056 .07",
                "00010203040506.7 ",
                "00010203040506.",
                "0001020304050607",

                "-0010203040506",
                "0001-203040506",
                "000102-3040506",
                "00010203-40506",
                "0001020304-506",
                "000102030405-6",
                "0001+203040506",
                "000102+3040506",
                "00010203+40506",
                "0001020304+506",
                "000102030405+6",
                " 0010203040506",
                "0001 203040506",
                "000102 3040506",
                "00010203 40506",
                "0001020304 506",
                "000102030405 6",
                "001 0203040506",
                "00012 03040506",
                "0001023 040506",
                "000102034 0506",
                "00010203045 06",
                "0001020304056 ",

                "-00102030405.07",
                "0001-2030405.07",
                "000102-30405.07",
                "00010203-405.07",
                "0001020304-5.07",
                "000102030405.-7",
                "+00102030405.07",
                "0001+2030405.07",
                "00010203+405.07",
                "0001020304+5.07",
                "000102030405.+7",
                " 00102030405.07",
                "0001 2030405.07",
                "000102 30405.07",
                "00010203 405.07",
                "0001020304 5.07",
                "000102030405. 7",
                "001 02030405.07",
                "00012 030405.07",
                "0001023 0405.07",
                "000102034 05.07",
                "00010203045 .07",
                "000102030405.7 ",
                "000102030405.",

                "-001020304.07",
                "0001-20304.07",
                "000102-304.07",
                "00010203-4.07",
                "0001020304.-7",
                "+001020304.07",
                "0001+20304.07",
                "00010203+4.07",
                "0001020304.+7",
                " 001020304.07",
                "0001 20304.07",
                "000102 304.07",
                "00010203 4.07",
                "0001020304. 7",
                "001 020304.07",
                "00012 0304.07",
                "0001023 04.07",
                "000102034 .07",
                "0001020304.7 ",
                "0001020304.",

                "00010203",
                "00010203040506Y",
                "0001010100+0001",
                "0001010100+00:01",
                "0001010100+01",

                "00010203040506.07+15",
                "00010203040506.07-15",
                "00010203040506.07+14:60",
                "00010203040506.07+1460",
                "00010203040506.07-1460",
                "00010203040506.07+00:60",
                "00010203040506.07-00:60",

                "00010203040506+15",
                "00010203040506-15",
                "00010203040506+14:60",
                "00010203040506+1460",
                "00010203040506-1460",
                "00010203040506+00:60",
                "00010203040506-00:60",

                "0001020304050.07",
                "00010203040.07",
                "000102030.07",
                "0001020304050",
                "00010203040",
                "000102030",
        )):
            with self.assertRaises(DecodeError):
                GeneralizedTime(data.encode("ascii"), ctx={"bered": True})
            data = data.replace(".", ",")
            with self.assertRaises(DecodeError):
                GeneralizedTime(data.encode("ascii"), ctx={"bered": True})

    @given(
        binary(
            min_size=(LEN_YYYYMMDDHHMMSSZ - 1) // 2,
            max_size=(LEN_YYYYMMDDHHMMSSZ - 1) // 2,
        ),
        binary(min_size=1, max_size=1),
        binary(
            min_size=(LEN_YYYYMMDDHHMMSSZ - 1) // 2,
            max_size=(LEN_YYYYMMDDHHMMSSZ - 1) // 2,
        ),
    )
    def test_junk(self, part0, part1, part2):
        junk = part0 + part1 + part2
        assume(not (set(junk) <= set(digits.encode("ascii"))))
        with self.assertRaises(DecodeError):
            GeneralizedTime().decode(
                GeneralizedTime.tag_default +
                len_encode(len(junk)) +
                junk
            )

    @given(
        binary(
            min_size=(LEN_YYYYMMDDHHMMSSDMZ - 1) // 2,
            max_size=(LEN_YYYYMMDDHHMMSSDMZ - 1) // 2,
        ),
        binary(min_size=1, max_size=1),
        binary(
            min_size=(LEN_YYYYMMDDHHMMSSDMZ - 1) // 2,
            max_size=(LEN_YYYYMMDDHHMMSSDMZ - 1) // 2,
        ),
    )
    def test_junk_dm(self, part0, part1, part2):
        junk = part0 + part1 + part2
        assume(not (set(junk) <= set(digits.encode("ascii"))))
        with self.assertRaises(DecodeError):
            GeneralizedTime().decode(
                GeneralizedTime.tag_default +
                len_encode(len(junk)) +
                junk
            )

    def test_ns_fractions(self):
        GeneralizedTime(b"20010101000000.000001Z")
        with self.assertRaisesRegex(DecodeError, "only microsecond fractions"):
            GeneralizedTime(b"20010101000000.0000001Z")

    def test_non_pure_integers(self):
        for data in ((
                # b"20000102030405Z,
                b"+2000102030405Z",
                b"2000+102030405Z",
                b"200001+2030405Z",
                b"20000102+30405Z",
                b"2000010203+405Z",
                b"200001020304+5Z",
                b"20000102030405.+6Z",
                b"20000102030405.-6Z",
                b"_2000102030405Z",
                b"2000_102030405Z",
                b"200001_2030405Z",
                b"20000102_30405Z",
                b"2000010203_405Z",
                b"200001020304_5Z",
                b"20000102030405._6Z",
                b"20000102030405.6_Z",
                b" 2000102030405Z",
                b"2000 102030405Z",
                b"200001 2030405Z",
                b"20000102 30405Z",
                b"2000010203 405Z",
                b"200001020304 5Z",
                b"20000102030405. 6Z",
                b"200 0102030405Z",
                b"20001 02030405Z",
                b"2000012 030405Z",
                b"200001023 0405Z",
                b"20000102034 05Z",
                b"2000010203045 Z",
                b"20000102030405.6 Z",
        )):
            with self.assertRaises(DecodeError):
                GeneralizedTime(data)

    def test_aware(self):
        with self.assertRaisesRegex(ValueError, "only naive"):
            GeneralizedTime(datetime(2000, 1, 1, 1, tzinfo=UTC))


class TestUTCTime(TimeMixin, CommonMixin, TestCase):
    base_klass = UTCTime
    omit_ms = True
    min_datetime = datetime(2000, 1, 1)
    max_datetime = datetime(2049, 12, 31)
    evgen_mode_skip_value = False

    def additional_symmetric_check(self, value, obj_encoded):
        pass

    def test_repr_not_ready(self):
        str(GeneralizedTime())
        repr(UTCTime())

    def test_x690_vector_valid(self):
        for data in ((
                b"920521000000Z",
                b"920622123421Z",
                b"920722132100Z",
        )):
            UTCTime(data)

    def test_x690_vector_invalid(self):
        for data in ((
                b"920520240000Z",
                b"9207221321Z",
        )):
            with self.assertRaises(DecodeError) as err:
                UTCTime(data)
            repr(err.exception)

    def test_go_vectors_invalid(self):
        for data in ((
                b"a10506234540Z",
                b"91a506234540Z",
                b"9105a6234540Z",
                b"910506a34540Z",
                b"910506334a40Z",
                b"91050633444aZ",
                b"910506334461Z",
                b"910506334400Za",
                b"000100000000Z",
                b"101302030405Z",
                b"100002030405Z",
                b"100100030405Z",
                b"100132030405Z",
                b"100231030405Z",
                b"100102240405Z",
                b"100102036005Z",
                b"100102030460Z",
                b"-100102030410Z",
                b"10-0102030410Z",
                b"10-0002030410Z",
                b"1001-02030410Z",
                b"100102-030410Z",
                b"10010203-0410Z",
                b"1001020304-10Z",
                # These ones are INVALID in *DER*, but accepted
                # by Go's encoding/asn1
                b"910506164540-0700",
                b"910506164540+0730",
                b"9105062345Z",
                b"5105062345Z",
        )):
            with self.assertRaises(DecodeError) as err:
                UTCTime(data)
            repr(err.exception)

    def test_go_vectors_valid(self):
        self.assertEqual(
            UTCTime(b"910506234540Z").todatetime(),
            datetime(1991, 5, 6, 23, 45, 40, 0),
        )

    def test_non_pure_integers(self):
        for data in ((
                # b"000102030405Z",
                b"+10102030405Z",
                b"00+102030405Z",
                b"0001+2030405Z",
                b"000102+30405Z",
                b"00010203+405Z",
                b"0001020304+5Z",
                b"_10102030405Z",
                b"00_102030405Z",
                b"0001_2030405Z",
                b"000102_30405Z",
                b"00010203_405Z",
                b"0001020304_5Z",
                b"00010203045_Z",
                b" 10102030405Z",
                b"00 102030405Z",
                b"0001 2030405Z",
                b"000102 30405Z",
                b"00010203 405Z",
                b"0001020304 5Z",
                b"1 0102030405Z",
                b"001 02030405Z",
                b"00012 030405Z",
                b"0001023 0405Z",
                b"000102034 05Z",
                b"00010203045 Z",
        )):
            with self.assertRaises(DecodeError):
                UTCTime(data)

    def test_x680_vector_valid_ber(self):
        for data, dt in ((
                (b"8201021200Z", datetime(1982, 1, 2, 12)),
                (b"8201020700-0500", datetime(1982, 1, 2, 12)),
                (b"0101021200Z", datetime(2001, 1, 2, 12)),
                (b"0101020700-0500", datetime(2001, 1, 2, 12)),
        )):
            data_der = UTCTime.tag_default + len_encode(len(data)) + data
            obj = UTCTime().decod(data_der, ctx={"bered": True})
            self.assertEqual(obj, dt)
            self.assertEqual(obj.todatetime(), dt)
            self.assertTrue(obj.ber_encoded)
            self.assertTrue(obj.bered)
            self.assertEqual(obj.ber_raw, data)
            self.assertNotEqual(obj.encode(), data_der)
            repr(obj)

    def test_go_vectors_valid_ber(self):
        for data in ((
                b"910506164540-0700",
                b"910506164540+0730",
                b"9105062345Z",
                b"5105062345Z",
        )):
            data = UTCTime.tag_default + len_encode(len(data)) + data
            obj = UTCTime().decod(data, ctx={"bered": True})
            self.assertTrue(obj.ber_encoded)
            self.assertTrue(obj.bered)
            self.assertNotEqual(obj.encode(), data)
            repr(obj)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_valid_ber(self, d):
        year = d.draw(integers(min_value=0, max_value=99))
        month = d.draw(integers(min_value=1, max_value=12))
        day = d.draw(integers(min_value=1, max_value=28))
        hours = d.draw(integers(min_value=0, max_value=23))
        minute = d.draw(integers(min_value=0, max_value=59))
        data = "%02d%02d%02d%02d%02d" % (year, month, day, hours, minute)
        dt = datetime(
            year + (2000 if year < 50 else 1900),
            month,
            day,
            hours,
            minute,
        )
        dered = False
        if d.draw(booleans()):
            dered = True
            seconds = d.draw(integers(min_value=0, max_value=59))
            data += "%02d" % seconds
            dt += timedelta(seconds=seconds)
        if d.draw(booleans()):
            data += "Z"
        else:
            dered = False
            offset_hour = d.draw(integers(min_value=0, max_value=13))
            offset_minute = d.draw(integers(min_value=0, max_value=59))
            offset = timedelta(seconds=offset_hour * 3600 + offset_minute * 60)
            if d.draw(booleans()):
                dt += offset
                data += "-"
            else:
                dt -= offset
                data += "+"
            data += "%02d%02d" % (offset_hour, offset_minute)
        data = data.encode("ascii")
        data_der = UTCTime.tag_default + len_encode(len(data)) + data
        obj = UTCTime().decod(data_der, ctx={"bered": True})
        self.assertEqual(obj, dt)
        self.assertEqual(obj.todatetime(), dt)
        self.assertEqual(obj.ber_encoded, not dered)
        self.assertEqual(obj.bered, not dered)
        self.assertEqual(obj.ber_raw, None if dered else data)
        self.assertEqual(obj.encode() == data_der, dered)
        repr(obj)
        bytes(obj)
        str(obj)

    def test_invalid_ber(self):
        for data in ((
                # b"0001020304Z",
                b"-101020304Z",
                b"00-1020304Z",
                b"0001-20304Z",
                b"000102-304Z",
                b"000102-104Z",
                b"00000203-4Z",
                b"+101020304Z",
                b"00+1020304Z",
                b"0001+20304Z",
                b"000102+304Z",
                b"000102+104Z",
                b"00000203+4Z",
                b" 101020304Z",
                b"00 1020304Z",
                b"0001 20304Z",
                b"000102 304Z",
                b"000102 104Z",
                b"00000203 4Z",
                b"1 01020304Z",
                b"001 020304Z",
                b"00012 0304Z",
                b"0001023 04Z",
                b"0001021 04Z",
                b"000002034 Z",
                b"0013020304Z",
                b"0001000304Z",
                b"0001320304Z",
                b"0001022404Z",
                b"0001020360Z",
                b"0002300304Z",
                b"0001020304",
                b"0001020304T",
                b"0001020304+",
                b"0001020304-",
                b"0001020304+0",
                b"0001020304+00",
                b"0001020304+000",
                b"0001020304+000Z",
                b"0001020304+0000Z",
                b"0001020304+-101",
                b"0001020304+01-1",
                b"0001020304+0060",
                b"0001020304+1401",
                b"5001010000+0001",
                b"000102030Z",
                b"0001020Z",
        )):
            with self.assertRaises(DecodeError):
                UTCTime(data, ctx={"bered": True})
            data = data[:8] + data[8+2:]
            with self.assertRaises(DecodeError):
                UTCTime(data, ctx={"bered": True})

        for data in ((
                # b"000102030405Z",
                b"-10102030405Z",
                b"00-102030405Z",
                b"0001-2030405Z",
                b"000102-30405Z",
                b"000102-10405Z",
                b"00000203-405Z",
                b"0000020304-5Z",
                b"+10102030405Z",
                b"00+102030405Z",
                b"0001+2030405Z",
                b"000102+30405Z",
                b"000102+10405Z",
                b"00000203+405Z",
                b"0000020304+5Z",
                b" 10102030405Z",
                b"00 102030405Z",
                b"0001 2030405Z",
                b"000102 30405Z",
                b"000102 10405Z",
                b"00000203 405Z",
                b"0000020304 5Z",
                b"1 0102030405Z",
                b"001 02030405Z",
                b"00012 030405Z",
                b"0001023 0405Z",
                b"0001021 0405Z",
                b"000002034 05Z",
                b"00000203045 Z",
                b"001302030405Z",
                b"000100030405Z",
                b"000132030405Z",
                b"000102240405Z",
                b"000102036005Z",
                b"000230030405Z",
                b"000102030460Z",
                b"000102030405",
                b"000102030405T",
                b"000102030405+",
                b"000102030405-",
                b"000102030405+0",
                b"000102030405+00",
                b"000102030405+000",
                b"000102030405+000Z",
                b"000102030405+0000Z",
                b"000102030405+-101",
                b"000102030405+01-1",
                b"000102030405+0060",
                b"000102030405+1401",
                b"500101000002+0003",
        )):
            with self.assertRaises(DecodeError):
                UTCTime(data, ctx={"bered": True})

    @given(integers(min_value=0, max_value=49))
    def test_pre50(self, year):
        self.assertEqual(
            UTCTime(("%02d1231235959Z" % year).encode("ascii")).todatetime().year,
            2000 + year,
        )

    @given(integers(min_value=50, max_value=99))
    def test_post50(self, year):
        self.assertEqual(
            UTCTime(("%02d1231235959Z" % year).encode("ascii")).todatetime().year,
            1900 + year,
        )

    @given(
        binary(
            min_size=(LEN_YYMMDDHHMMSSZ - 1) // 2,
            max_size=(LEN_YYMMDDHHMMSSZ - 1) // 2,
        ),
        binary(min_size=1, max_size=1),
        binary(
            min_size=(LEN_YYMMDDHHMMSSZ - 1) // 2,
            max_size=(LEN_YYMMDDHHMMSSZ - 1) // 2,
        ),
    )
    def test_junk(self, part0, part1, part2):
        junk = part0 + part1 + part2
        assume(not (set(junk) <= set(digits.encode("ascii"))))
        with self.assertRaises(DecodeError):
            UTCTime().decode(
                UTCTime.tag_default +
                len_encode(len(junk)) +
                junk
            )

    def test_aware(self):
        with self.assertRaisesRegex(ValueError, "only naive"):
            UTCTime(datetime(2000, 1, 1, 1, tzinfo=UTC))

    def test_raises_if_no_dateutil(self):
        with patch("pyderasn.tzUTC", new="missing"):
            with self.assertRaisesRegex(NotImplementedError, "dateutil"):
                UTCTime(datetime.now()).totzdatetime()

    def test_tzinfo_gives_datetime_with_tzutc_tzinfo(self):
        self.assertEqual(UTCTime(datetime.now()).totzdatetime().tzinfo, UTC)


@composite
def tlv_value_strategy(draw):
    tag_num = draw(integers(min_value=1))
    data = draw(binary())
    return b"".join((tag_encode(tag_num), len_encode(len(data)), data))


@composite
def any_values_strategy(draw, do_expl=False):
    value = draw(one_of(none(), tlv_value_strategy()))
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, expl, optional, _decoded)


class AnyInherited(Any):
    pass


class TestAny(CommonMixin, TestCase):
    base_klass = Any

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            Any(123)
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = Any(optional=optional)
        self.assertEqual(obj.optional, optional)

    @given(tlv_value_strategy())
    def test_ready(self, value):
        obj = Any()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        obj = Any(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(integers())
    def test_basic(self, value):
        integer_encoded = Integer(value).encode()
        for obj in (
                Any(integer_encoded),
                Any(Integer(value)),
                Any(Any(Integer(value))),
        ):
            self.assertSequenceEqual(bytes(obj), integer_encoded)
            self.assertEqual(
                obj.decode(obj.encode())[0].vlen,
                len(integer_encoded),
            )
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertSequenceEqual(obj.encode(), integer_encoded)

    @given(tlv_value_strategy(), tlv_value_strategy())
    def test_comparison(self, value1, value2):
        for klass in (Any, AnyInherited):
            obj1 = klass(value1)
            obj2 = klass(value2)
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == bytes(obj2), value1 == value2)

    @given(data_strategy())
    def test_call(self, d):
        for klass in (Any, AnyInherited):
            (
                value_initial,
                expl_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(any_values_strategy())
            obj_initial = klass(
                value_initial,
                expl_initial,
                optional_initial or False,
                _decoded_initial,
            )
            (
                value,
                expl,
                optional,
                _decoded,
            ) = d.draw(any_values_strategy(do_expl=True))
            obj = obj_initial(value, expl, optional)
            if obj.ready:
                value_expected = None if value is None else value
                self.assertEqual(obj, value_expected)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            self.assertEqual(obj.optional, optional)

    def test_simultaneous_impl_expl(self):
        # override it, as Any does not have implicit tag
        pass

    def test_decoded(self):
        # override it, as Any does not have implicit tag
        pass

    @given(any_values_strategy())
    def test_copy(self, values):
        for klass in (Any, AnyInherited):
            obj = klass(*values)
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj._value, obj_copied._value)

    @given(binary().map(OctetString))
    def test_stripped(self, value):
        obj = Any(value)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        tlv_value_strategy(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = Any(value, expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Any().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            Any().decode(
                Any.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        any_values_strategy(),
        integers().map(lambda x: Integer(x).encode()),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
        booleans(),
    )
    def test_symmetric(
            self,
            values,
            value,
            tag_expl,
            offset,
            tail_junk,
            decode_path,
            keep_memoryview,
    ):
        for klass in (Any, AnyInherited):
            _, _, optional, _decoded = values
            obj = klass(value=value, optional=optional, _decoded=_decoded)
            repr(obj)
            list(obj.pps())
            pprint(obj, big_blobs=True, with_decode_path=True)
            self.assertFalse(obj.expled)
            tag_class, _, tag_num = tag_decode(tag_strip(value)[0])
            self.assertEqual(obj.tag_order, (tag_class, tag_num))
            obj_encoded = obj.encode()
            self.assertEqual(encode2pass(obj), obj_encoded)
            obj_expled = obj(value, expl=tag_expl)
            self.assertTrue(obj_expled.expled)
            tag_class, _, tag_num = tag_decode(tag_expl)
            self.assertEqual(obj_expled.tag_order, (tag_class, tag_num))
            repr(obj_expled)
            list(obj_expled.pps())
            pprint(obj_expled, big_blobs=True, with_decode_path=True)
            obj_expled_encoded = obj_expled.encode()
            ctx_dummy["keep_memoryview"] = keep_memoryview
            ctx_copied = deepcopy(ctx_dummy)
            obj_decoded, tail = obj_expled.decode(
                obj_expled_encoded + tail_junk,
                offset=offset,
                ctx=ctx_copied,
            )
            self.assertDictEqual(ctx_copied, ctx_dummy)
            repr(obj_decoded)
            list(obj_decoded.pps())
            pprint(obj_decoded, big_blobs=True, with_decode_path=True)
            self.assertEqual(tail, tail_junk)
            self.assertEqual(obj_decoded, obj_expled)
            self.assertEqual(bytes(obj_decoded), bytes(obj_expled))
            self.assertEqual(bytes(obj_decoded), bytes(obj))
            self.assertIsInstance(
                obj_decoded._value,
                memoryview if keep_memoryview else bytes,
            )
            self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
            self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
            self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
            self.assertEqual(
                obj_decoded.expl_llen,
                len(len_encode(len(obj_encoded))),
            )
            self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
            self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
            self.assertEqual(
                obj_decoded.offset,
                offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
            )
            self.assertEqual(obj_decoded.expl_offset, offset)
            self.assertEqual(obj_decoded.tlen, 0)
            self.assertEqual(obj_decoded.llen, 0)
            self.assertEqual(obj_decoded.vlen, len(value))
            assert_exceeding_data(
                self,
                lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
                tail_junk,
            )

            evgens = list(obj_expled.decode_evgen(
                obj_expled_encoded + tail_junk,
                offset=offset,
                decode_path=decode_path,
                ctx=ctx_copied,
            ))
            self.assertEqual(len(evgens), 1)
            _decode_path, obj, tail = evgens[0]
            self.assertSequenceEqual(tail, tail_junk)
            self.assertEqual(_decode_path, decode_path)
            self.assertEqual(obj.expl_offset, offset)
            repr(obj)
            list(obj.pps())

    @given(
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0, max_value=3),
        integers(min_value=0),
        decode_path_strat,
        binary(),
    )
    def test_indefinite(self, expl, chunks, offset, decode_path, junk):
        chunk = Boolean(False, expl=expl).encode()
        encoded = (
            OctetString.tag_default +
            LENINDEF +
            b"".join([chunk] * chunks) +
            EOC
        )
        with self.assertRaises(LenIndefForm):
            Any().decode(
                encoded + junk,
                offset=offset,
                decode_path=decode_path,
            )
        obj, tail = Any().decode(
            encoded + junk,
            offset=offset,
            decode_path=decode_path,
            ctx={"bered": True},
        )
        self.assertSequenceEqual(tail, junk)
        self.assertEqual(obj.offset, offset)
        self.assertEqual(obj.tlvlen, len(encoded))
        self.assertTrue(obj.lenindef)
        self.assertFalse(obj.ber_encoded)
        self.assertTrue(obj.bered)
        obj = copy(obj)
        self.assertTrue(obj.lenindef)
        self.assertFalse(obj.ber_encoded)
        self.assertTrue(obj.bered)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        with self.assertRaises(NotEnoughData) as err:
            Any().decode(
                encoded[:-1],
                offset=offset,
                decode_path=decode_path,
                ctx={"bered": True},
            )
        self.assertEqual(err.exception.offset, offset + 1 + 1 + len(chunk) * chunks)
        self.assertEqual(err.exception.decode_path, decode_path + (str(chunks),))

        class SeqOf(SequenceOf):
            schema = Boolean(expl=expl)

        class Seq(Sequence):
            schema = (
                ("type", ObjectIdentifier(defines=((("value",), {
                    ObjectIdentifier("1.2.3"): SeqOf(impl=OctetString.tag_default),
                }),))),
                ("value", Any()),
            )
        seq = Seq((
            ("type", ObjectIdentifier("1.2.3")),
            ("value", Any(encoded)),
        ))
        seq_encoded = seq.encode()
        seq_decoded, _ = Seq().decode(seq_encoded, ctx={"bered": True})
        self.assertIsNotNone(seq_decoded["value"].defined)
        repr(seq_decoded)
        list(seq_decoded.pps())
        pprint(seq_decoded, big_blobs=True, with_decode_path=True)
        self.assertTrue(seq_decoded.bered)
        self.assertFalse(seq_decoded["type"].bered)
        self.assertTrue(seq_decoded["value"].bered)

        chunk = chunk[:-1] + b"\x01"
        chunks = b"".join([chunk] * (chunks + 1))
        encoded = OctetString.tag_default + len_encode(len(chunks)) + chunks
        seq = Seq((
            ("type", ObjectIdentifier("1.2.3")),
            ("value", Any(encoded)),
        ))
        seq_encoded = seq.encode()
        seq_decoded, _ = Seq().decode(seq_encoded, ctx={"bered": True})
        self.assertIsNotNone(seq_decoded["value"].defined)
        repr(seq_decoded)
        list(seq_decoded.pps())
        pprint(seq_decoded, big_blobs=True, with_decode_path=True)
        self.assertTrue(seq_decoded.bered)
        self.assertFalse(seq_decoded["type"].bered)
        self.assertTrue(seq_decoded["value"].bered)


@composite
def choice_values_strategy(draw, value_required=False, schema=None, do_expl=False):
    if schema is None:
        names = list(draw(sets(text_letters(), min_size=1, max_size=5)))
        tags = [{tag_type: tag_value} for tag_type, tag_value in draw(sets(
            one_of(
                tuples(just("impl"), integers(min_value=0).map(tag_encode)),
                tuples(just("expl"), integers(min_value=0).map(tag_ctxp)),
            ),
            min_size=len(names),
            max_size=len(names),
        ))]
        schema = [
            (name, Integer(**tag_kwargs))
            for name, tag_kwargs in zip(names, tags)
        ]
    value = None
    if value_required or draw(booleans()):
        value = draw(tuples(
            sampled_from([name for name, _ in schema]),
            integers().map(Integer),
        ))
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = draw(one_of(
        none(),
        tuples(sampled_from([name for name, _ in schema]), integers().map(Integer)),
    ))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (schema, value, expl, default, optional, _decoded)


class ChoiceInherited(Choice):
    pass


class TestChoice(CommonMixin, TestCase):
    class Wahl(Choice):
        schema = (("whatever", Boolean()),)
    base_klass = Wahl

    def test_schema_required(self):
        with self.assertRaisesRegex(ValueError, "schema must be specified"):
            Choice()

    def test_impl_forbidden(self):
        with self.assertRaisesRegex(ValueError, "no implicit tag allowed"):
            Choice(impl=b"whatever")

    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass(123)
        repr(err.exception)
        with self.assertRaises(ObjUnknown) as err:
            self.base_klass(("whenever", Boolean(False)))
        repr(err.exception)
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass(("whatever", Integer(123)))
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = self.base_klass(
            default=self.base_klass(("whatever", Boolean(False))),
            optional=optional,
        )
        self.assertTrue(obj.optional)

    @given(booleans())
    def test_ready(self, value):
        obj = self.base_klass()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertIsNone(obj["whatever"])
        with self.assertRaises(ObjNotReady) as err:
            obj.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(obj)
        obj["whatever"] = Boolean()
        self.assertFalse(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        obj["whatever"] = Boolean(value)
        self.assertTrue(obj.ready)
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)

    @given(booleans(), booleans())
    def test_comparison(self, value1, value2):
        class WahlInherited(self.base_klass):
            pass
        for klass in (self.base_klass, WahlInherited):
            obj1 = klass(("whatever", Boolean(value1)))
            obj2 = klass(("whatever", Boolean(value2)))
            self.assertEqual(obj1 == obj2, value1 == value2)
            self.assertEqual(obj1 != obj2, value1 != value2)
            self.assertEqual(obj1 == obj2._value, value1 == value2)
            self.assertFalse(obj1 == obj2._value[1])

    @given(data_strategy())
    def test_call(self, d):
        for klass in (Choice, ChoiceInherited):
            (
                schema_initial,
                value_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(choice_values_strategy())

            class Wahl(klass):
                schema = schema_initial
            obj_initial = Wahl(
                value=value_initial,
                expl=expl_initial,
                default=default_initial,
                optional=optional_initial or False,
                _decoded=_decoded_initial,
            )
            (
                _,
                value,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(choice_values_strategy(schema=schema_initial, do_expl=True))
            obj = obj_initial(value, expl, default, optional)
            if obj.ready:
                value_expected = default if value is None else value
                value_expected = (
                    default_initial if value_expected is None
                    else value_expected
                )
                self.assertEqual(obj.choice, value_expected[0])
                self.assertEqual(obj.value, int(value_expected[1]))
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            default_expect = default_initial if default is None else default
            if default_expect is not None:
                self.assertEqual(obj.default.choice, default_expect[0])
                self.assertEqual(obj.default.value, int(default_expect[1]))
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(obj.optional, optional)
            self.assertEqual(obj.specs, obj_initial.specs)

    def test_simultaneous_impl_expl(self):
        # override it, as Any does not have implicit tag
        pass

    def test_decoded(self):
        # override it, as Any does not have implicit tag
        pass

    @given(choice_values_strategy())
    def test_copy(self, values):
        _schema, value, expl, default, optional, _decoded = values

        class Wahl(self.base_klass):
            schema = _schema
        register_class(Wahl)
        obj = Wahl(
            value=value,
            expl=expl,
            default=default,
            optional=optional or False,
            _decoded=_decoded,
        )
        for copy_func in copy_funcs:
            obj_copied = copy_func(obj)
            self.assertIsNone(obj.tag)
            self.assertIsNone(obj_copied.tag)
            # hack for assert_copied_basic_fields
            obj.tag = "whatever"
            obj_copied.tag = "whatever"
            self.assert_copied_basic_fields(obj, obj_copied)
            obj.tag = None
            self.assertEqual(obj._value, obj_copied._value)
            self.assertEqual(obj.specs, obj_copied.specs)

    @given(booleans())
    def test_stripped(self, value):
        obj = self.base_klass(("whatever", Boolean(value)))
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        booleans(),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, value, tag_expl):
        obj = self.base_klass(("whatever", Boolean(value)), expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric(self, d):
        _schema, value, _, default, optional, _decoded = d.draw(
            choice_values_strategy(value_required=True)
        )
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))
        offset = d.draw(integers(min_value=0))
        tail_junk = d.draw(binary(max_size=5))
        decode_path = d.draw(decode_path_strat)

        class Wahl(self.base_klass):
            schema = _schema
        obj = Wahl(
            value=value,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertFalse(obj.expled)
        self.assertEqual(obj.tag_order, obj.value.tag_order)
        obj_encoded = obj.encode()
        self.assertEqual(encode2pass(obj), obj_encoded)
        obj_expled = obj(value, expl=tag_expl)
        self.assertTrue(obj_expled.expled)
        tag_class, _, tag_num = tag_decode(tag_expl)
        self.assertEqual(obj_expled.tag_order, (tag_class, tag_num))
        repr(obj_expled)
        list(obj_expled.pps())
        pprint(obj_expled, big_blobs=True, with_decode_path=True)
        obj_expled_encoded = obj_expled.encode()
        ctx_copied = deepcopy(ctx_dummy)
        obj_decoded, tail = obj_expled.decode(
            obj_expled_encoded + tail_junk,
            offset=offset,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        repr(obj_decoded)
        list(obj_decoded.pps())
        pprint(obj_decoded, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail, tail_junk)
        self.assertEqual(obj_decoded, obj_expled)
        self.assertEqual(obj_decoded.choice, obj_expled.choice)
        self.assertEqual(obj_decoded.value, obj_expled.value)
        self.assertEqual(obj_decoded.choice, obj.choice)
        self.assertEqual(obj_decoded.value, obj.value)
        self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
        self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
        self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
        self.assertEqual(
            obj_decoded.expl_llen,
            len(len_encode(len(obj_encoded))),
        )
        self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
        self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
        self.assertEqual(
            obj_decoded.offset,
            offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
        )
        self.assertEqual(obj_decoded.expl_offset, offset)
        self.assertSequenceEqual(
            obj_expled_encoded[
                obj_decoded.value.fulloffset - offset:
                obj_decoded.value.fulloffset + obj_decoded.value.fulllen - offset
            ],
            obj_encoded,
        )
        assert_exceeding_data(
            self,
            lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
            tail_junk,
        )

        evgens = list(obj_expled.decode_evgen(
            obj_expled_encoded + tail_junk,
            offset=offset,
            decode_path=decode_path,
            ctx=ctx_copied,
        ))
        self.assertEqual(len(evgens), 2)
        _decode_path, obj, tail = evgens[0]
        self.assertEqual(_decode_path, decode_path + (obj_decoded.choice,))
        _decode_path, obj, tail = evgens[1]
        self.assertSequenceEqual(tail, tail_junk)
        self.assertEqual(_decode_path, decode_path)
        self.assertEqual(obj.expl_offset, offset)
        repr(obj)
        list(obj.pps())

    @given(integers())
    def test_set_get(self, value):
        class Wahl(Choice):
            schema = (
                ("erste", Boolean()),
                ("zweite", Integer()),
            )
        obj = Wahl()
        with self.assertRaises(ObjUnknown) as err:
            obj["whatever"] = "whenever"
        with self.assertRaises(InvalidValueType) as err:
            obj["zweite"] = Boolean(False)
        obj["zweite"] = Integer(value)
        repr(err.exception)
        with self.assertRaises(ObjUnknown) as err:
            obj["whatever"]
        repr(err.exception)
        self.assertIsNone(obj["erste"])
        self.assertEqual(obj["zweite"], Integer(value))

    def test_tag_mismatch(self):
        class Wahl(Choice):
            schema = (
                ("erste", Boolean()),
            )
        int_encoded = Integer(123).encode()
        bool_encoded = Boolean(False).encode()
        obj = Wahl()
        obj.decode(bool_encoded)
        with self.assertRaises(TagMismatch):
            obj.decode(int_encoded)

    def test_tag_mismatch_underlying(self):
        class SeqOfBoolean(SequenceOf):
            schema = Boolean()

        class SeqOfInteger(SequenceOf):
            schema = Integer()

        class Wahl(Choice):
            schema = (
                ("erste", SeqOfBoolean()),
            )

        int_encoded = SeqOfInteger((Integer(123),)).encode()
        bool_encoded = SeqOfBoolean((Boolean(False),)).encode()
        obj = Wahl()
        obj.decode(bool_encoded)
        with self.assertRaises(TagMismatch) as err:
            obj.decode(int_encoded)
        self.assertEqual(err.exception.decode_path, ("erste", "0"))


@composite
def seq_values_strategy(draw, seq_klass, do_expl=False):
    value = None
    if draw(booleans()):
        value = seq_klass()
        value._value = draw(dictionaries(
            integers(),
            one_of(
                booleans().map(Boolean),
                integers().map(Integer),
            ),
        ))
    schema = None
    if draw(booleans()):
        schema = list(draw(dictionaries(
            integers(),
            one_of(
                booleans().map(Boolean),
                integers().map(Integer),
            ),
        )).items())
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = None
    if draw(booleans()):
        default = seq_klass()
        default._value = draw(dictionaries(
            integers(),
            one_of(
                booleans().map(Boolean),
                integers().map(Integer),
            ),
        ))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (value, schema, impl, expl, default, optional, _decoded)


@composite
def sequence_strategy(draw, seq_klass):
    inputs = draw(lists(
        one_of(
            tuples(just(Boolean), booleans(), one_of(none(), booleans())),
            tuples(just(Integer), integers(), one_of(none(), integers())),
        ),
        max_size=6,
    ))
    tags = draw(sets(
        integers(min_value=1),
        min_size=len(inputs),
        max_size=len(inputs),
    ))
    inits = [
        ({"expl": tag_ctxc(tag)} if expled else {"impl": tag_encode(tag)})
        for tag, expled in zip(tags, draw(lists(
            booleans(),
            min_size=len(inputs),
            max_size=len(inputs),
        )))
    ]
    empties = []
    for i, optional in enumerate(draw(lists(
            sampled_from(("required", "optional", "empty")),
            min_size=len(inputs),
            max_size=len(inputs),
    ))):
        if optional in ("optional", "empty"):
            inits[i]["optional"] = True
        if optional == "empty":
            empties.append(i)
    empties = set(empties)
    names = list(draw(sets(
        text_printable,
        min_size=len(inputs),
        max_size=len(inputs),
    )))
    schema = []
    for i, (klass, value, default) in enumerate(inputs):
        schema.append((names[i], klass(default=default, **inits[i])))
    seq_name = draw(text_letters())
    Seq = type(seq_name, (seq_klass,), {"schema": tuple(schema)})
    seq = Seq()
    expects = []
    for i, (klass, value, default) in enumerate(inputs):
        name = names[i]
        _, spec = schema[i]
        expect = {
            "name": name,
            "optional": False,
            "presented": False,
            "default_value": None if spec.default is None else default,
            "value": None,
        }
        if i in empties:
            expect["optional"] = True
        else:
            expect["presented"] = True
            expect["value"] = value
            if spec.optional:
                expect["optional"] = True
            if default is not None and default == value:
                expect["presented"] = False
            seq[name] = klass(value)
        expects.append(expect)
    return seq, expects


@composite
def sequences_strategy(draw, seq_klass):
    tags = draw(sets(integers(min_value=1), min_size=0, max_size=5))
    inits = [
        ({"expl": tag_ctxc(tag)} if expled else {"impl": tag_encode(tag)})
        for tag, expled in zip(tags, draw(lists(
            booleans(),
            min_size=len(tags),
            max_size=len(tags),
        )))
    ]
    defaulted = set(
        i for i, is_default in enumerate(draw(lists(
            booleans(),
            min_size=len(tags),
            max_size=len(tags),
        ))) if is_default
    )
    names = list(draw(sets(
        text_printable,
        min_size=len(tags),
        max_size=len(tags),
    )))
    seq_expectses = draw(lists(
        sequence_strategy(seq_klass=seq_klass),
        min_size=len(tags),
        max_size=len(tags),
    ))
    seqs = [seq for seq, _ in seq_expectses]
    schema = []
    for i, (name, seq) in enumerate(zip(names, seqs)):
        schema.append((
            name,
            seq(default=(seq if i in defaulted else None), **inits[i]),
        ))
    seq_name = draw(text_letters())
    Seq = type(seq_name, (seq_klass,), {"schema": tuple(schema)})
    seq_outer = Seq()
    expect_outers = []
    for name, (seq_inner, expects_inner) in zip(names, seq_expectses):
        expect = {
            "name": name,
            "expects": expects_inner,
            "presented": False,
        }
        seq_outer[name] = seq_inner
        if seq_outer.specs[name].default is None:
            expect["presented"] = True
        expect_outers.append(expect)
    return seq_outer, expect_outers


class SeqMixin(object):
    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass(123)
        repr(err.exception)

    def test_invalid_value_type_set(self):
        class Seq(self.base_klass):
            schema = (("whatever", Boolean()),)
        seq = Seq()
        with self.assertRaises(InvalidValueType) as err:
            seq["whatever"] = Integer(123)
        repr(err.exception)

    @given(booleans())
    def test_optional(self, optional):
        obj = self.base_klass(default=self.base_klass(), optional=optional)
        self.assertTrue(obj.optional)

    @given(data_strategy())
    def test_ready(self, d):
        ready = {
            str(i): v for i, v in enumerate(d.draw(lists(
                booleans(),
                min_size=1,
                max_size=3,
            )))
        }
        non_ready = {
            str(i + len(ready)): v for i, v in enumerate(d.draw(lists(
                booleans(),
                min_size=1,
                max_size=3,
            )))
        }
        schema_input = []
        for name in d.draw(permutations(
                list(ready.keys()) + list(non_ready.keys()),
        )):
            schema_input.append((name, Boolean()))

        class Seq(self.base_klass):
            schema = tuple(schema_input)
        seq = Seq()
        for name in ready.keys():
            seq[name]
            seq[name] = Boolean()
        self.assertFalse(seq.ready)
        repr(seq)
        list(seq.pps())
        pprint(seq, big_blobs=True, with_decode_path=True)
        for name, value in ready.items():
            seq[name] = Boolean(value)
        self.assertFalse(seq.ready)
        repr(seq)
        list(seq.pps())
        pprint(seq, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            seq.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(seq)
        for name, value in non_ready.items():
            seq[name] = Boolean(value)
        self.assertTrue(seq.ready)
        repr(seq)
        list(seq.pps())
        pprint(seq, big_blobs=True, with_decode_path=True)

    @given(data_strategy())
    def test_call(self, d):
        class SeqInherited(self.base_klass):
            pass
        for klass in (self.base_klass, SeqInherited):
            (
                value_initial,
                schema_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial,
                _decoded_initial,
            ) = d.draw(seq_values_strategy(seq_klass=klass))
            obj_initial = klass(
                value_initial,
                schema_initial,
                impl_initial,
                expl_initial,
                default_initial,
                optional_initial or False,
                _decoded_initial,
            )
            (
                value,
                _,
                impl,
                expl,
                default,
                optional,
                _decoded,
            ) = d.draw(seq_values_strategy(
                seq_klass=klass,
                do_expl=impl_initial is None,
            ))
            obj = obj_initial(value, impl, expl, default, optional)
            value_expected = default if value is None else value
            value_expected = (
                default_initial if value_expected is None
                else value_expected
            )
            self.assertEqual(obj._value, getattr(value_expected, "_value", {}))
            self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
            self.assertEqual(obj.expl_tag, expl or expl_initial)
            self.assertEqual(
                {} if obj.default is None else obj.default._value,
                getattr(default_initial if default is None else default, "_value", {}),
            )
            if obj.default is None:
                optional = optional_initial if optional is None else optional
                optional = False if optional is None else optional
            else:
                optional = True
            self.assertEqual(list(obj.specs.items()), schema_initial or [])
            self.assertEqual(obj.optional, optional)

    @given(data_strategy())
    def test_copy(self, d):
        class SeqInherited(self.base_klass):
            pass
        register_class(SeqInherited)
        for klass in (self.base_klass, SeqInherited):
            values = d.draw(seq_values_strategy(seq_klass=klass))
            obj = klass(*values)
            for copy_func in copy_funcs:
                obj_copied = copy_func(obj)
                self.assert_copied_basic_fields(obj, obj_copied)
                self.assertEqual(obj.specs, obj_copied.specs)
                self.assertEqual(obj._value, obj_copied._value)

    @given(data_strategy())
    def test_stripped(self, d):
        value = d.draw(integers())
        tag_impl = tag_encode(d.draw(integers(min_value=1)))

        class Seq(self.base_klass):
            impl = tag_impl
            schema = (("whatever", Integer()),)
        seq = Seq()
        seq["whatever"] = Integer(value)
        with self.assertRaises(NotEnoughData):
            seq.decode(seq.encode()[:-1])

    @given(data_strategy())
    def test_stripped_expl(self, d):
        value = d.draw(integers())
        tag_expl = tag_ctxc(d.draw(integers(min_value=1)))

        class Seq(self.base_klass):
            expl = tag_expl
            schema = (("whatever", Integer()),)
        seq = Seq()
        seq["whatever"] = Integer(value)
        with self.assertRaises(NotEnoughData):
            seq.decode(seq.encode()[:-1])

    @given(integers(min_value=3), binary(min_size=2))
    def test_non_tag_mismatch_raised(self, junk_tag_num, junk):
        junk = tag_encode(junk_tag_num) + junk
        try:
            _, _, len_encoded = tag_strip(memoryview(junk))
            len_decode(len_encoded)
        except Exception:
            assume(True)
        else:
            assume(False)

        class Seq(self.base_klass):
            schema = (
                ("whatever", Integer()),
                ("junk", Any()),
                ("whenever", Integer()),
            )
        seq = Seq()
        seq["whatever"] = Integer(123)
        seq["junk"] = Any(junk)
        seq["whenever"] = Integer(123)
        with self.assertRaises(DecodeError):
            seq.decode(seq.encode())

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                self.base_klass.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    def _assert_expects(self, seq, expects):
        for expect in expects:
            self.assertEqual(
                seq.specs[expect["name"]].optional,
                expect["optional"],
            )
            if expect["default_value"] is not None:
                self.assertEqual(
                    seq.specs[expect["name"]].default,
                    expect["default_value"],
                )
            if expect["presented"]:
                self.assertIn(expect["name"], seq)
                self.assertEqual(seq[expect["name"]], expect["value"])

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric(self, d):
        seq, expects = d.draw(sequence_strategy(seq_klass=self.base_klass))
        tail_junk = d.draw(binary(max_size=5))
        decode_path = d.draw(decode_path_strat)
        self.assertTrue(seq.ready)
        self.assertFalse(seq.decoded)
        self._assert_expects(seq, expects)
        repr(seq)
        list(seq.pps())
        pprint(seq, big_blobs=True, with_decode_path=True)
        self.assertTrue(seq.ready)
        seq_encoded = seq.encode()
        self.assertEqual(encode2pass(seq), seq_encoded)
        seq_encoded_cer = encode_cer(seq)
        self.assertNotEqual(seq_encoded_cer, seq_encoded)
        self.assertSequenceEqual(
            seq.decod(seq_encoded_cer, ctx={"bered": True}).encode(),
            seq_encoded,
        )
        seq_decoded, tail = seq.decode(seq_encoded + tail_junk)
        self.assertFalse(seq_decoded.lenindef)
        self.assertFalse(seq_decoded.ber_encoded)
        self.assertFalse(seq_decoded.bered)

        t, _, lv = tag_strip(seq_encoded)
        _, _, v = len_decode(lv)
        seq_encoded_lenindef = t + LENINDEF + v + EOC
        with self.assertRaises(DecodeError):
            seq.decode(seq_encoded_lenindef)
        ctx_copied = deepcopy(ctx_dummy)
        ctx_copied["bered"] = True
        seq_decoded_lenindef, tail_lenindef = seq.decode(
            seq_encoded_lenindef + tail_junk,
            ctx=ctx_copied,
        )
        del ctx_copied["bered"]
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertTrue(seq_decoded_lenindef.lenindef)
        self.assertTrue(seq_decoded_lenindef.bered)
        seq_decoded_lenindef = copy(seq_decoded_lenindef)
        self.assertTrue(seq_decoded_lenindef.lenindef)
        self.assertTrue(seq_decoded_lenindef.bered)
        with self.assertRaises(DecodeError):
            seq.decode(seq_encoded_lenindef[:-1], ctx={"bered": True})
        with self.assertRaises(DecodeError):
            seq.decode(seq_encoded_lenindef[:-2], ctx={"bered": True})
        repr(seq_decoded_lenindef)
        list(seq_decoded_lenindef.pps())
        pprint(seq_decoded_lenindef, big_blobs=True, with_decode_path=True)
        self.assertTrue(seq_decoded_lenindef.ready)

        for decoded, decoded_tail, encoded in (
                (seq_decoded, tail, seq_encoded),
                (seq_decoded_lenindef, tail_lenindef, seq_encoded_lenindef),
        ):
            self.assertEqual(decoded_tail, tail_junk)
            self._assert_expects(decoded, expects)
            self.assertEqual(seq, decoded)
            self.assertEqual(decoded.encode(), seq_encoded)
            self.assertEqual(decoded.tlvlen, len(encoded))
            for expect in expects:
                if not expect["presented"]:
                    self.assertNotIn(expect["name"], decoded)
                    continue
                self.assertIn(expect["name"], decoded)
                obj = decoded[expect["name"]]
                self.assertTrue(obj.decoded)
                offset = obj.expl_offset if obj.expled else obj.offset
                tlvlen = obj.expl_tlvlen if obj.expled else obj.tlvlen
                self.assertSequenceEqual(
                    seq_encoded[offset:offset + tlvlen],
                    obj.encode(),
                )

            evgens = list(seq.decode_evgen(
                encoded + decoded_tail,
                decode_path=decode_path,
                ctx={"bered": True},
            ))
            self.assertEqual(len(evgens), len(list(decoded._values_for_encoding())) + 1)
            for _decode_path, obj, _ in evgens[:-1]:
                self.assertEqual(_decode_path[:-1], decode_path)
                repr(obj)
                list(obj.pps())
            _decode_path, obj, tail = evgens[-1]
            self.assertEqual(_decode_path, decode_path)
            repr(obj)
            list(obj.pps())

        assert_exceeding_data(
            self,
            lambda: seq.decod(seq_encoded_lenindef + tail_junk, ctx={"bered": True}),
            tail_junk,
        )

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_symmetric_with_seq(self, d):
        seq, expect_outers = d.draw(sequences_strategy(seq_klass=self.base_klass))
        self.assertTrue(seq.ready)
        seq_encoded = seq.encode()
        self.assertEqual(encode2pass(seq), seq_encoded)
        seq_decoded, tail = seq.decode(seq_encoded)
        self.assertEqual(tail, b"")
        self.assertTrue(seq.ready)
        self.assertEqual(seq, seq_decoded)
        self.assertEqual(seq_decoded.encode(), seq_encoded)
        for expect_outer in expect_outers:
            if not expect_outer["presented"]:
                self.assertNotIn(expect_outer["name"], seq_decoded)
                continue
            self.assertIn(expect_outer["name"], seq_decoded)
            obj = seq_decoded[expect_outer["name"]]
            self.assertTrue(obj.decoded)
            offset = obj.expl_offset if obj.expled else obj.offset
            tlvlen = obj.expl_tlvlen if obj.expled else obj.tlvlen
            self.assertSequenceEqual(
                seq_encoded[offset:offset + tlvlen],
                obj.encode(),
            )
            self._assert_expects(obj, expect_outer["expects"])

    @given(data_strategy())
    def test_default_disappears(self, d):
        _schema = list(d.draw(dictionaries(
            text_letters(),
            sets(integers(), min_size=2, max_size=2),
            min_size=1,
        )).items())

        class Seq(self.base_klass):
            schema = [
                (n, Integer(default=d))
                for n, (_, d) in _schema
            ]
        seq = Seq()
        for name, (value, _) in _schema:
            seq[name] = Integer(value)
        self.assertEqual(len(seq._value), len(_schema))
        empty_seq = b"".join((self.base_klass.tag_default, len_encode(0)))
        self.assertGreater(len(seq.encode()), len(empty_seq))
        for name, (_, default) in _schema:
            seq[name] = Integer(default)
        self.assertEqual(len(seq._value), 0)
        self.assertSequenceEqual(seq.encode(), empty_seq)

    @given(data_strategy())
    def test_encoded_default_not_accepted(self, d):
        _schema = list(d.draw(dictionaries(
            text_letters(),
            integers(),
            min_size=1,
        )).items())
        tags = [tag_encode(tag) for tag in d.draw(sets(
            integers(min_value=1),
            min_size=len(_schema),
            max_size=len(_schema),
        ))]

        class Wahl(Choice):
            schema = (("int", Integer()),)

        class SeqWithoutDefault(self.base_klass):
            schema = [
                (n, Wahl(expl=t))
                for (n, _), t in zip(_schema, tags)
            ]
        seq_without_default = SeqWithoutDefault()
        for name, value in _schema:
            seq_without_default[name] = Wahl(("int", Integer(value)))
        seq_encoded = seq_without_default.encode()
        seq_without_default.decode(seq_encoded)
        self.assertEqual(
            len(list(seq_without_default.decode_evgen(seq_encoded))),
            len(_schema) * 2 + 1,
        )

        class SeqWithDefault(self.base_klass):
            schema = [
                (n, Wahl(default=Wahl(("int", Integer(v))), expl=t))
                for (n, v), t in zip(_schema, tags)
            ]
        seq_with_default = SeqWithDefault()
        with self.assertRaisesRegex(DecodeError, "DEFAULT value met"):
            seq_with_default.decode(seq_encoded)
        with self.assertRaisesRegex(DecodeError, "DEFAULT value met"):
            list(seq_with_default.decode_evgen(seq_encoded))
        for ctx in ({"bered": True}, {"allow_default_values": True}):
            seq_decoded, _ = seq_with_default.decode(seq_encoded, ctx=ctx)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)
            seq_decoded = copy(seq_decoded)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)
            for name, value in _schema:
                self.assertEqual(seq_decoded[name], seq_with_default[name])
                self.assertEqual(seq_decoded[name].value, value)
            self.assertEqual(
                len(list(seq_with_default.decode_evgen(seq_encoded, ctx=ctx))),
                len(_schema) + 1,
            )

        seq_without_default = SeqWithoutDefault()
        for name, value in _schema:
            seq_without_default[name] = Wahl(("int", Integer(value + 1)))
        seq_encoded = seq_without_default.encode()
        seq_with_default.decode(seq_encoded)
        self.assertEqual(
            len(list(seq_with_default.decode_evgen(seq_encoded))),
            len(_schema) + 1,
        )

    @given(data_strategy())
    def test_missing_from_spec(self, d):
        names = list(d.draw(sets(text_letters(), min_size=2)))
        tags = [tag_encode(tag) for tag in d.draw(sets(
            integers(min_value=1),
            min_size=len(names),
            max_size=len(names),
        ))]
        names_tags = [(name, tag) for tag, name in sorted(zip(tags, names))]

        class SeqFull(self.base_klass):
            schema = [(n, Integer(impl=t)) for n, t in names_tags]
        seq_full = SeqFull()
        for i, name in enumerate(names):
            seq_full[name] = Integer(i)
        seq_encoded = seq_full.encode()
        altered = names_tags[:-2] + names_tags[-1:]

        class SeqMissing(self.base_klass):
            schema = [(n, Integer(impl=t)) for n, t in altered]
        seq_missing = SeqMissing()
        with self.assertRaises(TagMismatch):
            seq_missing.decode(seq_encoded)
        with self.assertRaises(TagMismatch):
            list(seq_missing.decode_evgen(seq_encoded))

    def test_bered(self):
        class Seq(self.base_klass):
            schema = (("underlying", Boolean()),)
        encoded = Boolean.tag_default + len_encode(1) + b"\x01"
        encoded = Seq.tag_default + len_encode(len(encoded)) + encoded
        decoded, _ = Seq().decode(encoded, ctx={"bered": True})
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)
        decoded = copy(decoded)
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)

        class Seq(self.base_klass):
            schema = (("underlying", OctetString()),)
        encoded = (
            tag_encode(form=TagFormConstructed, num=4) +
            LENINDEF +
            OctetString(b"whatever").encode() +
            EOC
        )
        encoded = Seq.tag_default + len_encode(len(encoded)) + encoded
        with self.assertRaises(DecodeError):
            Seq().decode(encoded)
        with self.assertRaises(DecodeError):
            list(Seq().decode_evgen(encoded))
        list(Seq().decode_evgen(encoded, ctx={"bered": True}))
        decoded, _ = Seq().decode(encoded, ctx={"bered": True})
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)
        decoded = copy(decoded)
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)


class TestSequence(SeqMixin, CommonMixin, TestCase):
    base_klass = Sequence

    @given(
        integers(),
        binary(min_size=1),
    )
    def test_remaining(self, value, junk):
        class Seq(Sequence):
            schema = (
                ("whatever", Integer()),
            )
        int_encoded = Integer(value).encode()
        junked = b"".join((
            Sequence.tag_default,
            len_encode(len(int_encoded + junk)),
            int_encoded + junk,
        ))
        with self.assertRaisesRegex(DecodeError, "remaining"):
            Seq().decode(junked)

    @given(sets(text_letters(), min_size=2))
    def test_obj_unknown(self, names):
        missing = names.pop()

        class Seq(Sequence):
            schema = [(n, Boolean()) for n in names]
        seq = Seq()
        with self.assertRaises(ObjUnknown) as err:
            seq[missing]
        repr(err.exception)
        with self.assertRaises(ObjUnknown) as err:
            seq[missing] = Boolean()
        repr(err.exception)

    def test_x690_vector(self):
        class Seq(Sequence):
            schema = (
                ("name", IA5String()),
                ("ok", Boolean()),
            )
        seq = Seq().decode(hexdec("300A1605536d6974680101FF"))[0]
        self.assertEqual(seq["name"], "Smith")
        self.assertEqual(seq["ok"], True)


class TestSet(SeqMixin, CommonMixin, TestCase):
    base_klass = Set

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_sorted(self, d):
        class DummySeq(Sequence):
            schema = (("null", Null()),)

        tag_nums = d.draw(sets(integers(min_value=1), min_size=1, max_size=50))
        _, _, dummy_seq_tag_num = tag_decode(DummySeq.tag_default)
        assume(any(i > dummy_seq_tag_num for i in tag_nums))
        tag_nums -= set([dummy_seq_tag_num])
        _schema = [(str(i), OctetString(impl=tag_encode(i))) for i in tag_nums]
        _schema.append(("seq", DummySeq()))

        class Seq(Set):
            schema = d.draw(permutations(_schema))
        seq = Seq()
        for name, _ in _schema:
            if name != "seq":
                seq[name] = OctetString(name.encode("ascii"))
        seq["seq"] = DummySeq((("null", Null()),))

        seq_encoded = seq.encode()
        seq_decoded, _ = seq.decode(seq_encoded)
        seq_encoded_expected = []
        for tag_num in sorted(tag_nums | set([dummy_seq_tag_num])):
            if tag_num == dummy_seq_tag_num:
                seq_encoded_expected.append(seq["seq"].encode())
            else:
                seq_encoded_expected.append(seq[str(tag_num)].encode())
        self.assertSequenceEqual(
            seq_encoded[seq_decoded.tlen + seq_decoded.llen:],
            b"".join(seq_encoded_expected),
        )

        encoded = b"".join(seq[str(i)].encode() for i in tag_nums)
        encoded += seq["seq"].encode()
        seq_encoded = b"".join((
            Set.tag_default,
            len_encode(len(encoded)),
            encoded,
        ))
        with self.assertRaisesRegex(DecodeError, "unordered SET"):
            seq.decode(seq_encoded)
        for ctx in ({"bered": True}, {"allow_unordered_set": True}):
            seq_decoded, _ = Seq().decode(seq_encoded, ctx=ctx)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)
            seq_decoded = copy(seq_decoded)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)

    def test_same_value_twice(self):
        class Seq(Set):
            schema = (
                ("bool", Boolean()),
                ("int", Integer()),
            )

        encoded = b"".join((
            Integer(123).encode(),
            Integer(234).encode(),
            Boolean(True).encode(),
        ))
        encoded = Seq.tag_default + len_encode(len(encoded)) + encoded
        with self.assertRaises(TagMismatch):
            Seq().decod(encoded, ctx={"allow_unordered_set": True})


@composite
def seqof_values_strategy(draw, schema=None, do_expl=False):
    if schema is None:
        schema = draw(sampled_from((Boolean(), Integer())))
    bound_min, bound_max = sorted(draw(sets(
        integers(min_value=0, max_value=10),
        min_size=2,
        max_size=2,
    )))
    if isinstance(schema, Boolean):
        values_generator = booleans().map(Boolean)
    elif isinstance(schema, Integer):
        values_generator = integers().map(Integer)
    values_generator = lists(
        values_generator,
        min_size=bound_min,
        max_size=bound_max,
    )
    values = draw(one_of(none(), values_generator))
    impl = None
    expl = None
    if do_expl:
        expl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    else:
        impl = draw(one_of(none(), integers(min_value=1).map(tag_encode)))
    default = draw(one_of(none(), values_generator))
    optional = draw(one_of(none(), booleans()))
    _decoded = (
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
        draw(integers(min_value=0)),
    )
    return (
        schema,
        values,
        (bound_min, bound_max),
        impl,
        expl,
        default,
        optional,
        _decoded,
    )


class SeqOfMixin(object):
    def test_invalid_value_type(self):
        with self.assertRaises(InvalidValueType) as err:
            self.base_klass(123)
        repr(err.exception)

    def test_invalid_values_type(self):
        class SeqOf(self.base_klass):
            schema = Integer()
        with self.assertRaises(InvalidValueType) as err:
            SeqOf([Integer(123), Boolean(False), Integer(234)])
        repr(err.exception)

    def test_schema_required(self):
        with self.assertRaisesRegex(ValueError, "schema must be specified"):
            self.base_klass.__mro__[1]()

    @given(booleans(), booleans(), binary(min_size=1), binary(min_size=1))
    def test_comparison(self, value1, value2, tag1, tag2):
        class SeqOf(self.base_klass):
            schema = Boolean()
        obj1 = SeqOf([Boolean(value1)])
        obj2 = SeqOf([Boolean(value2)])
        self.assertEqual(obj1 == obj2, value1 == value2)
        self.assertEqual(obj1 != obj2, value1 != value2)
        self.assertEqual(obj1 == list(obj2), value1 == value2)
        self.assertEqual(obj1 == tuple(obj2), value1 == value2)
        obj1 = SeqOf([Boolean(value1)], impl=tag1)
        obj2 = SeqOf([Boolean(value1)], impl=tag2)
        self.assertEqual(obj1 == obj2, tag1 == tag2)
        self.assertEqual(obj1 != obj2, tag1 != tag2)

    @given(lists(booleans()))
    def test_iter(self, values):
        class SeqOf(self.base_klass):
            schema = Boolean()
        obj = SeqOf([Boolean(value) for value in values])
        self.assertEqual(len(obj), len(values))
        for i, value in enumerate(obj):
            self.assertEqual(value, values[i])

    @given(data_strategy())
    def test_ready(self, d):
        ready = [Integer(v) for v in d.draw(lists(
            integers(),
            min_size=1,
            max_size=3,
        ))]
        non_ready = [
            Integer() for _ in
            range(d.draw(integers(min_value=1, max_value=5)))
        ]

        class SeqOf(self.base_klass):
            schema = Integer()
        values = d.draw(permutations(ready + non_ready))
        seqof = SeqOf()
        for value in values:
            seqof.append(value)
        self.assertFalse(seqof.ready)
        repr(seqof)
        list(seqof.pps())
        pprint(seqof, big_blobs=True, with_decode_path=True)
        with self.assertRaises(ObjNotReady) as err:
            seqof.encode()
        repr(err.exception)
        with self.assertRaises(ObjNotReady) as err:
            encode2pass(seqof)
        for i, value in enumerate(values):
            self.assertEqual(seqof[i], value)
            if not seqof[i].ready:
                seqof[i] = Integer(i)
        self.assertTrue(seqof.ready)
        repr(seqof)
        list(seqof.pps())
        pprint(seqof, big_blobs=True, with_decode_path=True)

    def test_spec_mismatch(self):
        class SeqOf(self.base_klass):
            schema = Integer()
        seqof = SeqOf()
        seqof.append(Integer(123))
        with self.assertRaises(ValueError):
            seqof.append(Boolean(False))
        with self.assertRaises(ValueError):
            seqof[0] = Boolean(False)

    @given(data_strategy())
    def test_bounds_satisfied(self, d):
        class SeqOf(self.base_klass):
            schema = Boolean()
        bound_min = d.draw(integers(min_value=0, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = [Boolean()] * d.draw(integers(min_value=bound_min, max_value=bound_max))
        SeqOf(value=value, bounds=(bound_min, bound_max))

    @given(data_strategy())
    def test_bounds_unsatisfied(self, d):
        class SeqOf(self.base_klass):
            schema = Boolean()
        bound_min = d.draw(integers(min_value=1, max_value=1 << 7))
        bound_max = d.draw(integers(min_value=bound_min, max_value=1 << 7))
        value = [Boolean(False)] * d.draw(integers(min_value=0, max_value=bound_min - 1))
        with self.assertRaises(BoundsError) as err:
            SeqOf(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            SeqOf(bounds=(bound_min, bound_max)).decode(
                SeqOf(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            SeqOf(bounds=(bound_min, bound_max)).decode(
                encode2pass(SeqOf(value))
            )
        value = [Boolean(True)] * d.draw(integers(
            min_value=bound_max + 1,
            max_value=bound_max + 10,
        ))
        with self.assertRaises(BoundsError) as err:
            SeqOf(value=value, bounds=(bound_min, bound_max))
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            SeqOf(bounds=(bound_min, bound_max)).decode(
                SeqOf(value).encode()
            )
        repr(err.exception)
        with self.assertRaisesRegex(DecodeError, "bounds") as err:
            SeqOf(bounds=(bound_min, bound_max)).decode(
                encode2pass(SeqOf(value))
            )

    @given(integers(min_value=1, max_value=10))
    def test_out_of_bounds(self, bound_max):
        class SeqOf(self.base_klass):
            schema = Integer()
            bounds = (0, bound_max)
        seqof = SeqOf()
        for _ in range(bound_max):
            seqof.append(Integer(123))
        with self.assertRaises(BoundsError):
            seqof.append(Integer(123))

    @given(data_strategy())
    def test_call(self, d):
        (
            schema_initial,
            value_initial,
            bounds_initial,
            impl_initial,
            expl_initial,
            default_initial,
            optional_initial,
            _decoded_initial,
        ) = d.draw(seqof_values_strategy())

        class SeqOf(self.base_klass):
            schema = schema_initial
        obj_initial = SeqOf(
            value=value_initial,
            bounds=bounds_initial,
            impl=impl_initial,
            expl=expl_initial,
            default=default_initial,
            optional=optional_initial or False,
            _decoded=_decoded_initial,
        )
        (
            _,
            value,
            bounds,
            impl,
            expl,
            default,
            optional,
            _decoded,
        ) = d.draw(seqof_values_strategy(
            schema=schema_initial,
            do_expl=impl_initial is None,
        ))
        if (default is None) and (obj_initial.default is not None):
            bounds = None
        if (
                (bounds is None) and
                (value is not None) and
                (bounds_initial is not None) and
                not (bounds_initial[0] <= len(value) <= bounds_initial[1])
        ):
            value = None
        if (
                (bounds is None) and
                (default is not None) and
                (bounds_initial is not None) and
                not (bounds_initial[0] <= len(default) <= bounds_initial[1])
        ):
            default = None
        obj = obj_initial(
            value=value,
            bounds=bounds,
            impl=impl,
            expl=expl,
            default=default,
            optional=optional,
        )
        if obj.ready:
            value_expected = default if value is None else value
            value_expected = (
                default_initial if value_expected is None
                else value_expected
            )
            value_expected = () if value_expected is None else value_expected
            self.assertEqual(obj, value_expected)
        self.assertEqual(obj.tag, impl or impl_initial or obj.tag_default)
        self.assertEqual(obj.expl_tag, expl or expl_initial)
        self.assertEqual(
            obj.default,
            default_initial if default is None else default,
        )
        if obj.default is None:
            optional = optional_initial if optional is None else optional
            optional = False if optional is None else optional
        else:
            optional = True
        self.assertEqual(obj.optional, optional)
        self.assertEqual(
            (obj._bound_min, obj._bound_max),
            bounds or bounds_initial or (0, float("+inf")),
        )

    @given(seqof_values_strategy())
    def test_copy(self, values):
        _schema, value, bounds, impl, expl, default, optional, _decoded = values

        class SeqOf(self.base_klass):
            schema = _schema
        register_class(SeqOf)
        obj = SeqOf(
            value=value,
            bounds=bounds,
            impl=impl,
            expl=expl,
            default=default,
            optional=optional or False,
            _decoded=_decoded,
        )
        for copy_func in copy_funcs:
            obj_copied = copy_func(obj)
            self.assert_copied_basic_fields(obj, obj_copied)
            self.assertEqual(obj._bound_min, obj_copied._bound_min)
            self.assertEqual(obj._bound_max, obj_copied._bound_max)
            self.assertEqual(obj._value, obj_copied._value)

    @given(
        lists(binary()),
        integers(min_value=1).map(tag_encode),
    )
    def test_stripped(self, values, tag_impl):
        class SeqOf(self.base_klass):
            schema = OctetString()
        obj = SeqOf([OctetString(v) for v in values], impl=tag_impl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        lists(binary()),
        integers(min_value=1).map(tag_ctxc),
    )
    def test_stripped_expl(self, values, tag_expl):
        class SeqOf(self.base_klass):
            schema = OctetString()
        obj = SeqOf([OctetString(v) for v in values], expl=tag_expl)
        with self.assertRaises(NotEnoughData):
            obj.decode(obj.encode()[:-1])

    @given(
        integers(min_value=31),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_tag(self, tag, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                tag_encode(tag)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(
        integers(min_value=128),
        integers(min_value=0),
        decode_path_strat,
    )
    def test_bad_len(self, l, offset, decode_path):
        with self.assertRaises(DecodeError) as err:
            self.base_klass().decode(
                self.base_klass.tag_default + len_encode(l)[:-1],
                offset=offset,
                decode_path=decode_path,
            )
        repr(err.exception)
        self.assertEqual(err.exception.offset, offset)
        self.assertEqual(err.exception.decode_path, decode_path)

    @given(binary(min_size=1))
    def test_tag_mismatch(self, impl):
        assume(impl != self.base_klass.tag_default)
        with self.assertRaises(TagMismatch):
            self.base_klass(impl=impl).decode(self.base_klass().encode())

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(
        seqof_values_strategy(schema=Integer()),
        lists(integers().map(Integer)),
        integers(min_value=1).map(tag_ctxc),
        integers(min_value=0),
        binary(max_size=5),
        decode_path_strat,
    )
    def test_symmetric(self, values, value, tag_expl, offset, tail_junk, decode_path):
        _, _, _, _, _, default, optional, _decoded = values

        class SeqOf(self.base_klass):
            schema = Integer()
        obj = SeqOf(
            value=value,
            default=default,
            optional=optional,
            _decoded=_decoded,
        )
        repr(obj)
        list(obj.pps())
        pprint(obj, big_blobs=True, with_decode_path=True)
        self.assertFalse(obj.expled)
        obj_encoded = obj.encode()
        self.assertEqual(encode2pass(obj), obj_encoded)
        obj_encoded_cer = encode_cer(obj)
        self.assertNotEqual(obj_encoded_cer, obj_encoded)
        self.assertSequenceEqual(
            obj.decod(obj_encoded_cer, ctx={"bered": True}).encode(),
            obj_encoded,
        )
        obj_expled = obj(value, expl=tag_expl)
        self.assertTrue(obj_expled.expled)
        repr(obj_expled)
        list(obj_expled.pps())
        pprint(obj_expled, big_blobs=True, with_decode_path=True)
        obj_expled_encoded = obj_expled.encode()
        ctx_copied = deepcopy(ctx_dummy)
        obj_decoded, tail = obj_expled.decode(
            obj_expled_encoded + tail_junk,
            offset=offset,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        repr(obj_decoded)
        list(obj_decoded.pps())
        pprint(obj_decoded, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail, tail_junk)
        self._test_symmetric_compare_objs(obj_decoded, obj_expled)
        self.assertSequenceEqual(obj_decoded.encode(), obj_expled_encoded)
        self.assertSequenceEqual(obj_decoded.expl_tag, tag_expl)
        self.assertEqual(obj_decoded.expl_tlen, len(tag_expl))
        self.assertEqual(
            obj_decoded.expl_llen,
            len(len_encode(len(obj_encoded))),
        )
        self.assertEqual(obj_decoded.tlvlen, len(obj_encoded))
        self.assertEqual(obj_decoded.expl_vlen, len(obj_encoded))
        self.assertEqual(
            obj_decoded.offset,
            offset + obj_decoded.expl_tlen + obj_decoded.expl_llen,
        )
        self.assertEqual(obj_decoded.expl_offset, offset)
        for obj_inner in obj_decoded:
            self.assertIn(obj_inner, obj_decoded)
            self.assertSequenceEqual(
                obj_inner.encode(),
                obj_expled_encoded[
                    obj_inner.offset - offset:
                    obj_inner.offset + obj_inner.tlvlen - offset
                ],
            )

        t, _, lv = tag_strip(obj_encoded)
        _, _, v = len_decode(lv)
        obj_encoded_lenindef = t + LENINDEF + v + EOC
        with self.assertRaises(DecodeError):
            obj.decode(obj_encoded_lenindef)
        obj_decoded_lenindef, tail_lenindef = obj.decode(
            obj_encoded_lenindef + tail_junk,
            ctx={"bered": True},
        )
        self.assertTrue(obj_decoded_lenindef.lenindef)
        self.assertTrue(obj_decoded_lenindef.bered)
        obj_decoded_lenindef = copy(obj_decoded_lenindef)
        self.assertTrue(obj_decoded_lenindef.lenindef)
        self.assertTrue(obj_decoded_lenindef.bered)
        repr(obj_decoded_lenindef)
        list(obj_decoded_lenindef.pps())
        pprint(obj_decoded_lenindef, big_blobs=True, with_decode_path=True)
        self.assertEqual(tail_lenindef, tail_junk)
        self.assertEqual(obj_decoded_lenindef.tlvlen, len(obj_encoded_lenindef))
        with self.assertRaises(DecodeError):
            obj.decode(obj_encoded_lenindef[:-1], ctx={"bered": True})
        with self.assertRaises(DecodeError):
            obj.decode(obj_encoded_lenindef[:-2], ctx={"bered": True})

        evgens = list(obj.decode_evgen(
            obj_encoded_lenindef + tail_junk,
            decode_path=decode_path,
            ctx={"bered": True},
        ))
        self.assertEqual(len(evgens), len(obj_decoded_lenindef) + 1)
        for i, (_decode_path, obj, _) in enumerate(evgens[:-1]):
            self.assertEqual(_decode_path, decode_path + (str(i),))
            repr(obj)
            list(obj.pps())
        _decode_path, obj, tail = evgens[-1]
        self.assertEqual(_decode_path, decode_path)
        repr(obj)
        list(obj.pps())

        assert_exceeding_data(
            self,
            lambda: obj_expled.decod(obj_expled_encoded + tail_junk),
            tail_junk,
        )

    def test_bered(self):
        class SeqOf(self.base_klass):
            schema = Boolean()
        encoded = Boolean(False).encode()
        encoded += Boolean.tag_default + len_encode(1) + b"\x01"
        encoded = SeqOf.tag_default + len_encode(len(encoded)) + encoded
        with self.assertRaises(DecodeError):
            SeqOf().decode(encoded)
        decoded, _ = SeqOf().decode(encoded, ctx={"bered": True})
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)
        decoded = copy(decoded)
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)

        class SeqOf(self.base_klass):
            schema = OctetString()
        encoded = OctetString(b"whatever").encode()
        encoded += (
            tag_encode(form=TagFormConstructed, num=4) +
            LENINDEF +
            OctetString(b"whatever").encode() +
            EOC
        )
        encoded = SeqOf.tag_default + len_encode(len(encoded)) + encoded
        with self.assertRaises(DecodeError):
            SeqOf().decode(encoded)
        decoded, _ = SeqOf().decode(encoded, ctx={"bered": True})
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)
        decoded = copy(decoded)
        self.assertFalse(decoded.ber_encoded)
        self.assertFalse(decoded.lenindef)
        self.assertTrue(decoded.bered)


class TestSequenceOf(SeqOfMixin, CommonMixin, TestCase):
    class SeqOf(SequenceOf):
        schema = "whatever"
    base_klass = SeqOf

    def _test_symmetric_compare_objs(self, obj1, obj2):
        self.assertEqual(obj1, obj2)
        self.assertSequenceEqual(list(obj1), list(obj2))

    def test_iterator_pickling(self):
        class SeqOf(SequenceOf):
            schema = Integer()
        register_class(SeqOf)
        seqof = SeqOf()
        pickle_dumps(seqof)
        seqof = seqof(iter(range(10)))
        with self.assertRaisesRegex(ValueError, "iterator"):
            pickle_dumps(seqof)

    def test_iterator_bounds(self):
        class SeqOf(SequenceOf):
            schema = Integer()
            bounds = (10, 20)
        seqof = None

        def gen(n):
            for i in range(n):
                yield Integer(i)
        for n in (9, 21):
            seqof = SeqOf(gen(n))
            self.assertTrue(seqof.ready)
            with self.assertRaises(BoundsError):
                seqof.encode()
            self.assertFalse(seqof.ready)
            seqof = seqof(gen(n))
            self.assertTrue(seqof.ready)
            with self.assertRaises(BoundsError):
                encode_cer(seqof)
            self.assertFalse(seqof.ready)

    def test_iterator_twice(self):
        class SeqOf(SequenceOf):
            schema = Integer()
            bounds = (1, float("+inf"))

        def gen():
            for i in range(10):
                yield Integer(i)
        seqof = SeqOf(gen())
        self.assertTrue(seqof.ready)
        seqof.encode()
        self.assertFalse(seqof.ready)
        register_class(SeqOf)
        pickle_dumps(seqof)

    def test_iterator_2pass(self):
        class SeqOf(SequenceOf):
            schema = Integer()
            bounds = (1, float("+inf"))

        def gen():
            for i in range(10):
                yield Integer(i)
        seqof = SeqOf(gen())
        self.assertTrue(seqof.ready)
        _, state = seqof.encode1st()
        self.assertFalse(seqof.ready)
        seqof = seqof(gen())
        self.assertTrue(seqof.ready)
        buf = BytesIO()
        seqof.encode2nd(buf.write, iter(state))
        self.assertSequenceEqual(
            [int(i) for i in seqof.decod(buf.getvalue())],
            list(gen()),
        )

    def test_non_ready_bound_min(self):
        class SeqOf(SequenceOf):
            schema = Integer()
            bounds = (1, float("+inf"))
        seqof = SeqOf()
        self.assertFalse(seqof.ready)


class TestSetOf(SeqOfMixin, CommonMixin, TestCase):
    class SeqOf(SetOf):
        schema = "whatever"
    base_klass = SeqOf

    def _test_symmetric_compare_objs(self, obj1, obj2):
        self.assertSetEqual(
            set(int(v) for v in obj1),
            set(int(v) for v in obj2),
        )

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_sorted(self, d):
        values = [OctetString(v) for v in d.draw(lists(binary()))]

        class Seq(SetOf):
            schema = OctetString()
        seq = Seq(values)
        seq_encoded = seq.encode()
        seq_decoded, _ = seq.decode(seq_encoded)
        self.assertSequenceEqual(
            seq_encoded[seq_decoded.tlen + seq_decoded.llen:],
            b"".join(sorted([v.encode() for v in values])),
        )

    @settings(max_examples=LONG_TEST_MAX_EXAMPLES)
    @given(data_strategy())
    def test_unsorted(self, d):
        values = [OctetString(v).encode() for v in d.draw(sets(
            binary(min_size=1, max_size=5),
            min_size=2,
            max_size=5,
        ))]
        values = d.draw(permutations(values))
        assume(values != sorted(values))
        encoded = b"".join(values)
        seq_encoded = b"".join((
            SetOf.tag_default,
            len_encode(len(encoded)),
            encoded,
        ))

        class Seq(SetOf):
            schema = OctetString()
        seq = Seq()
        with self.assertRaisesRegex(DecodeError, "unordered SET OF"):
            seq.decode(seq_encoded)

        for ctx in ({"bered": True}, {"allow_unordered_set": True}):
            seq_decoded, _ = Seq().decode(seq_encoded, ctx=ctx)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)
            seq_decoded = copy(seq_decoded)
            self.assertTrue(seq_decoded.ber_encoded)
            self.assertTrue(seq_decoded.bered)
            self.assertSequenceEqual(
                [obj.encode() for obj in seq_decoded],
                values,
            )


class TestGoMarshalVectors(TestCase):
    def runTest(self):
        self.assertSequenceEqual(Integer(10).encode(), hexdec("02010a"))
        self.assertSequenceEqual(Integer(127).encode(), hexdec("02017f"))
        self.assertSequenceEqual(Integer(128).encode(), hexdec("02020080"))
        self.assertSequenceEqual(Integer(-128).encode(), hexdec("020180"))
        self.assertSequenceEqual(Integer(-129).encode(), hexdec("0202ff7f"))

        class Seq(Sequence):
            schema = (
                ("erste", Integer()),
                ("zweite", Integer(optional=True))
            )
        seq = Seq()
        seq["erste"] = Integer(64)
        self.assertSequenceEqual(seq.encode(), hexdec("3003020140"))
        seq["erste"] = Integer(0x123456)
        self.assertSequenceEqual(seq.encode(), hexdec("30050203123456"))
        seq["erste"] = Integer(64)
        seq["zweite"] = Integer(65)
        self.assertSequenceEqual(seq.encode(), hexdec("3006020140020141"))

        class NestedSeq(Sequence):
            schema = (
                ("nest", Seq()),
            )
        seq["erste"] = Integer(127)
        seq["zweite"] = None
        nested = NestedSeq()
        nested["nest"] = seq
        self.assertSequenceEqual(nested.encode(), hexdec("3005300302017f"))

        self.assertSequenceEqual(
            OctetString(b"\x01\x02\x03").encode(),
            hexdec("0403010203"),
        )

        class Seq(Sequence):
            schema = (
                ("erste", Integer(impl=tag_encode(5, klass=TagClassContext))),
            )
        seq = Seq()
        seq["erste"] = Integer(64)
        self.assertSequenceEqual(seq.encode(), hexdec("3003850140"))

        class Seq(Sequence):
            schema = (
                ("erste", Integer(expl=tag_ctxc(5))),
            )
        seq = Seq()
        seq["erste"] = Integer(64)
        self.assertSequenceEqual(seq.encode(), hexdec("3005a503020140"))

        class Seq(Sequence):
            schema = (
                ("erste", Null(
                    impl=tag_encode(0, klass=TagClassContext),
                    optional=True,
                )),
            )
        seq = Seq()
        seq["erste"] = Null()
        self.assertSequenceEqual(seq.encode(), hexdec("30028000"))
        seq["erste"] = None
        self.assertSequenceEqual(seq.encode(), hexdec("3000"))

        self.assertSequenceEqual(
            UTCTime(datetime(1970, 1, 1, 0, 0)).encode(),
            hexdec("170d3730303130313030303030305a"),
        )
        self.assertSequenceEqual(
            UTCTime(datetime(2009, 11, 15, 22, 56, 16)).encode(),
            hexdec("170d3039313131353232353631365a"),
        )
        self.assertSequenceEqual(
            GeneralizedTime(datetime(2100, 4, 5, 12, 1, 1)).encode(),
            hexdec("180f32313030303430353132303130315a"),
        )

        class Seq(Sequence):
            schema = (
                ("erste", GeneralizedTime()),
            )
        seq = Seq()
        seq["erste"] = GeneralizedTime(datetime(2009, 11, 15, 22, 56, 16))
        self.assertSequenceEqual(
            seq.encode(),
            hexdec("3011180f32303039313131353232353631365a"),
        )

        self.assertSequenceEqual(
            BitString((1, b"\x80")).encode(),
            hexdec("03020780"),
        )
        self.assertSequenceEqual(
            BitString((12, b"\x81\xF0")).encode(),
            hexdec("03030481f0"),
        )

        self.assertSequenceEqual(
            ObjectIdentifier("1.2.3.4").encode(),
            hexdec("06032a0304"),
        )
        self.assertSequenceEqual(
            ObjectIdentifier("1.2.840.133549.1.1.5").encode(),
            hexdec("06092a864888932d010105"),
        )
        self.assertSequenceEqual(
            ObjectIdentifier("2.100.3").encode(),
            hexdec("0603813403"),
        )

        self.assertSequenceEqual(
            PrintableString("test").encode(),
            hexdec("130474657374"),
        )
        self.assertSequenceEqual(
            PrintableString("x" * 127).encode(),
            hexdec("137F" + "78" * 127),
        )
        self.assertSequenceEqual(
            PrintableString("x" * 128).encode(),
            hexdec("138180" + "78" * 128),
        )
        self.assertSequenceEqual(UTF8String("Σ").encode(), hexdec("0c02cea3"))

        class Seq(Sequence):
            schema = (
                ("erste", IA5String()),
            )
        seq = Seq()
        seq["erste"] = IA5String("test")
        self.assertSequenceEqual(seq.encode(), hexdec("3006160474657374"))

        class Seq(Sequence):
            schema = (
                ("erste", PrintableString()),
            )
        seq = Seq()
        seq["erste"] = PrintableString("test")
        self.assertSequenceEqual(seq.encode(), hexdec("3006130474657374"))
        # Asterisk is actually not allowable
        pyderasn.PRINTABLE_ALLOWABLE_CHARS |= set(b"*")
        seq["erste"] = PrintableString("test*")
        self.assertSequenceEqual(seq.encode(), hexdec("30071305746573742a"))
        pyderasn.PRINTABLE_ALLOWABLE_CHARS -= set(b"*")

        class Seq(Sequence):
            schema = (
                ("erste", Any(optional=True)),
                ("zweite", Integer()),
            )
        seq = Seq()
        seq["zweite"] = Integer(64)
        self.assertSequenceEqual(seq.encode(), hexdec("3003020140"))

        class Seq(SetOf):
            schema = Integer()
        seq = Seq()
        seq.append(Integer(10))
        self.assertSequenceEqual(seq.encode(), hexdec("310302010a"))

        class _SeqOf(SequenceOf):
            schema = PrintableString()

        class SeqOf(SequenceOf):
            schema = _SeqOf()
        _seqof = _SeqOf()
        _seqof.append(PrintableString("1"))
        seqof = SeqOf()
        seqof.append(_seqof)
        self.assertSequenceEqual(seqof.encode(), hexdec("30053003130131"))

        class Seq(Sequence):
            schema = (
                ("erste", Integer(default=1)),
            )
        seq = Seq()
        seq["erste"] = Integer(0)
        self.assertSequenceEqual(seq.encode(), hexdec("3003020100"))
        seq["erste"] = Integer(1)
        self.assertSequenceEqual(seq.encode(), hexdec("3000"))
        seq["erste"] = Integer(2)
        self.assertSequenceEqual(seq.encode(), hexdec("3003020102"))


class TestPP(TestCase):
    @given(data_strategy())
    def test_oid_printing(self, d):
        oids = {
            str(ObjectIdentifier(k)): v * 2
            for k, v in d.draw(dictionaries(
                oid_strategy(),
                text_letters(),
                min_size=1,
            )).items()
        }
        chosen = d.draw(sampled_from(sorted(oids)))
        chosen_id = oids[chosen]
        pp = _pp(asn1_type_name=ObjectIdentifier.asn1_type_name, value=chosen)
        self.assertNotIn(chosen_id, pp_console_row(pp))
        self.assertIn(
            chosen_id,
            pp_console_row(pp, oid_maps=[{'whatever': 'whenever'}, oids]),
        )


class TestAutoAddSlots(TestCase):
    def runTest(self):
        class Inher(Integer):
            pass

        with self.assertRaises(AttributeError):
            inher = Inher()
            inher.unexistent = "whatever"


class TestOIDDefines(TestCase):
    @given(data_strategy())
    def runTest(self, d):
        value_names = list(d.draw(sets(text_letters(), min_size=1, max_size=10)))
        value_name_chosen = d.draw(sampled_from(value_names))
        oids = [
            ObjectIdentifier(oid)
            for oid in d.draw(sets(oid_strategy(), min_size=2, max_size=10))
        ]
        oid_chosen = d.draw(sampled_from(oids))
        values = d.draw(lists(
            integers(),
            min_size=len(value_names),
            max_size=len(value_names),
        ))
        for definable_class in (Any, OctetString, BitString):
            _schema = [
                ("type", ObjectIdentifier(defines=(((value_name_chosen,), {
                    oid: Integer() for oid in oids[:-1]
                }),))),
            ]
            for i, value_name in enumerate(value_names):
                _schema.append((value_name, definable_class(expl=tag_ctxp(i))))

            class Seq(Sequence):
                schema = _schema
            seq = Seq()
            for value_name, value in zip(value_names, values):
                seq[value_name] = definable_class(Integer(value).encode())
            seq["type"] = oid_chosen
            seq, _ = Seq().decode(seq.encode())
            for value_name in value_names:
                if value_name == value_name_chosen:
                    continue
                self.assertIsNone(seq[value_name].defined)
            if value_name_chosen in oids[:-1]:
                self.assertIsNotNone(seq[value_name_chosen].defined)
                self.assertEqual(seq[value_name_chosen].defined[0], oid_chosen)
                self.assertIsInstance(seq[value_name_chosen].defined[1], Integer)
            repr(seq)
            list(seq.pps())
            pprint(seq, big_blobs=True, with_decode_path=True)


class TestDefinesByPath(TestCase):
    def test_generated(self):
        class Seq(Sequence):
            schema = (
                ("type", ObjectIdentifier()),
                ("value", OctetString(expl=tag_ctxc(123))),
            )

        class SeqInner(Sequence):
            schema = (
                ("typeInner", ObjectIdentifier()),
                ("valueInner", Any()),
            )

        class PairValue(SetOf):
            schema = Any()

        class Pair(Sequence):
            schema = (
                ("type", ObjectIdentifier()),
                ("value", PairValue()),
            )

        class Pairs(SequenceOf):
            schema = Pair()

        (
            type_integered,
            type_sequenced,
            type_innered,
            type_octet_stringed,
        ) = [
            ObjectIdentifier(oid)
            for oid in sets(oid_strategy(), min_size=4, max_size=4).example()
        ]
        seq_integered = Seq()
        seq_integered["type"] = type_integered
        seq_integered["value"] = OctetString(Integer(123).encode())
        seq_integered_raw = seq_integered.encode()

        pairs = Pairs()
        pairs_input = (
            (type_octet_stringed, OctetString(b"whatever")),
            (type_integered, Integer(123)),
            (type_octet_stringed, OctetString(b"whenever")),
            (type_integered, Integer(234)),
        )
        for t, v in pairs_input:
            pairs.append(Pair((
                ("type", t),
                ("value", PairValue((Any(v),))),
            )))
        seq_inner = SeqInner()
        seq_inner["typeInner"] = type_innered
        seq_inner["valueInner"] = Any(pairs)
        seq_sequenced = Seq()
        seq_sequenced["type"] = type_sequenced
        seq_sequenced["value"] = OctetString(seq_inner.encode())
        seq_sequenced_raw = seq_sequenced.encode()
        repr(seq_sequenced)
        list(seq_sequenced.pps())
        pprint(seq_sequenced, big_blobs=True, with_decode_path=True)

        defines_by_path = []
        ctx_copied = deepcopy(ctx_dummy)
        seq_integered, _ = Seq().decode(
            seq_integered_raw,
            ctx=ctx_copied,
        )
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertIsNone(seq_integered["value"].defined)
        defines_by_path.append(
            (("type",), ((("value",), {
                type_integered: Integer(),
                type_sequenced: SeqInner(),
            }),))
        )
        ctx_copied["defines_by_path"] = defines_by_path
        seq_integered, _ = Seq().decode(
            seq_integered_raw,
            ctx=ctx_copied,
        )
        del ctx_copied["defines_by_path"]
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertIsNotNone(seq_integered["value"].defined)
        self.assertEqual(seq_integered["value"].defined[0], type_integered)
        self.assertEqual(seq_integered["value"].defined[1], Integer(123))
        self.assertTrue(seq_integered_raw[
            seq_integered["value"].defined[1].offset:
        ].startswith(Integer(123).encode()))
        repr(seq_integered)
        list(seq_integered.pps())
        pprint(seq_integered, big_blobs=True, with_decode_path=True)

        ctx_copied["defines_by_path"] = defines_by_path
        seq_sequenced, _ = Seq().decode(
            seq_sequenced_raw,
            ctx=ctx_copied,
        )
        del ctx_copied["defines_by_path"]
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertIsNotNone(seq_sequenced["value"].defined)
        self.assertEqual(seq_sequenced["value"].defined[0], type_sequenced)
        seq_inner = seq_sequenced["value"].defined[1]
        self.assertIsNone(seq_inner["valueInner"].defined)
        repr(seq_sequenced)
        list(seq_sequenced.pps())
        pprint(seq_sequenced, big_blobs=True, with_decode_path=True)

        defines_by_path.append((
            ("value", DecodePathDefBy(type_sequenced), "typeInner"),
            ((("valueInner",), {type_innered: Pairs()}),),
        ))
        ctx_copied["defines_by_path"] = defines_by_path
        seq_sequenced, _ = Seq().decode(
            seq_sequenced_raw,
            ctx=ctx_copied,
        )
        del ctx_copied["defines_by_path"]
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertIsNotNone(seq_sequenced["value"].defined)
        self.assertEqual(seq_sequenced["value"].defined[0], type_sequenced)
        seq_inner = seq_sequenced["value"].defined[1]
        self.assertIsNotNone(seq_inner["valueInner"].defined)
        self.assertEqual(seq_inner["valueInner"].defined[0], type_innered)
        pairs = seq_inner["valueInner"].defined[1]
        for pair in pairs:
            self.assertIsNone(pair["value"][0].defined)
        repr(seq_sequenced)
        list(seq_sequenced.pps())
        pprint(seq_sequenced, big_blobs=True, with_decode_path=True)

        defines_by_path.append((
            (
                "value",
                DecodePathDefBy(type_sequenced),
                "valueInner",
                DecodePathDefBy(type_innered),
                any,
                "type",
            ),
            ((("value",), {
                type_integered: Integer(),
                type_octet_stringed: OctetString(),
            }),),
        ))
        ctx_copied["defines_by_path"] = defines_by_path
        seq_sequenced, _ = Seq().decode(
            seq_sequenced_raw,
            ctx=ctx_copied,
        )
        del ctx_copied["defines_by_path"]
        self.assertDictEqual(ctx_copied, ctx_dummy)
        self.assertIsNotNone(seq_sequenced["value"].defined)
        self.assertEqual(seq_sequenced["value"].defined[0], type_sequenced)
        seq_inner = seq_sequenced["value"].defined[1]
        self.assertIsNotNone(seq_inner["valueInner"].defined)
        self.assertEqual(seq_inner["valueInner"].defined[0], type_innered)
        pairs_got = seq_inner["valueInner"].defined[1]
        for pair_input, pair_got in zip(pairs_input, pairs_got):
            self.assertEqual(pair_got["value"][0].defined[0], pair_input[0])
            self.assertEqual(pair_got["value"][0].defined[1], pair_input[1])
        repr(seq_sequenced)
        list(seq_sequenced.pps())
        pprint(seq_sequenced, big_blobs=True, with_decode_path=True)

    @given(oid_strategy(), integers())
    def test_simple(self, oid, tgt):
        class Inner(Sequence):
            schema = (
                ("oid", ObjectIdentifier(defines=((("..", "tgt"), {
                    ObjectIdentifier(oid): Integer(),
                }),))),
            )

        class Outer(Sequence):
            schema = (
                ("inner", Inner()),
                ("tgt", OctetString()),
            )

        inner = Inner()
        inner["oid"] = ObjectIdentifier(oid)
        outer = Outer()
        outer["inner"] = inner
        outer["tgt"] = OctetString(Integer(tgt).encode())
        decoded, _ = Outer().decode(outer.encode())
        self.assertEqual(decoded["tgt"].defined[1], Integer(tgt))

    def test_remaining_data(self):
        oid = ObjectIdentifier("1.2.3")

        class Seq(Sequence):
            schema = (
                ("oid", ObjectIdentifier(defines=((("tgt",), {
                    oid: Integer(),
                }),))),
                ("tgt", OctetString()),
            )

        seq = Seq((
            ("oid", oid),
            ("tgt", OctetString(Integer(123).encode() + b"junk")),
        ))
        with self.assertRaisesRegex(DecodeError, "remaining data"):
            Seq().decode(seq.encode())

    def test_remaining_data_seqof(self):
        oid = ObjectIdentifier("1.2.3")

        class SeqOf(SetOf):
            schema = OctetString()

        class Seq(Sequence):
            schema = (
                ("oid", ObjectIdentifier(defines=((("tgt",), {
                    oid: Integer(),
                }),))),
                ("tgt", SeqOf()),
            )

        seq = Seq((
            ("oid", oid),
            ("tgt", SeqOf([OctetString(Integer(123).encode() + b"junk")])),
        ))
        with self.assertRaisesRegex(DecodeError, "remaining data"):
            Seq().decode(seq.encode())


class TestAbsDecodePath(TestCase):
    @given(
        lists(text(alphabet=ascii_letters, min_size=1)).map(tuple),
        lists(text(alphabet=ascii_letters, min_size=1), min_size=1).map(tuple),
    )
    def test_concat(self, decode_path, rel_path):
        dp = abs_decode_path(decode_path, rel_path)
        self.assertSequenceEqual(dp, decode_path + rel_path)
        repr(dp)

    @given(
        lists(text(alphabet=ascii_letters, min_size=1)).map(tuple),
        lists(text(alphabet=ascii_letters, min_size=1), min_size=1).map(tuple),
    )
    def test_abs(self, decode_path, rel_path):
        self.assertSequenceEqual(
            abs_decode_path(decode_path, ("/",) + rel_path),
            rel_path,
        )

    @given(
        lists(text(alphabet=ascii_letters, min_size=1), min_size=5).map(tuple),
        integers(min_value=1, max_value=3),
        lists(text(alphabet=ascii_letters, min_size=1), min_size=1).map(tuple),
    )
    def test_dots(self, decode_path, number_of_dots, rel_path):
        self.assertSequenceEqual(
            abs_decode_path(decode_path, tuple([".."] * number_of_dots) + rel_path),
            decode_path[:-number_of_dots] + rel_path,
        )


class TestStrictDefaultExistence(TestCase):
    @given(data_strategy())
    def runTest(self, d):
        count = d.draw(integers(min_value=1, max_value=10))
        chosen = d.draw(integers(min_value=0, max_value=count - 1))
        _schema = [
            ("int%d" % i, Integer(expl=tag_ctxc(i + 1)))
            for i in range(count)
        ]
        for klass in (Sequence, Set):
            class Seq(klass):
                schema = _schema
            seq = Seq()
            for i in range(count):
                seq["int%d" % i] = Integer(123)
            raw = seq.encode()
            chosen_choice = "int%d" % chosen
            seq.specs[chosen_choice] = seq.specs[chosen_choice](default=123)
            with self.assertRaisesRegex(DecodeError, "DEFAULT value met"):
                seq.decode(raw)
            decoded, _ = seq.decode(raw, ctx={"allow_default_values": True})
            self.assertTrue(decoded.ber_encoded)
            self.assertTrue(decoded.bered)
            decoded = copy(decoded)
            self.assertTrue(decoded.ber_encoded)
            self.assertTrue(decoded.bered)
            decoded, _ = seq.decode(raw, ctx={"bered": True})
            self.assertTrue(decoded.ber_encoded)
            self.assertTrue(decoded.bered)
            decoded = copy(decoded)
            self.assertTrue(decoded.ber_encoded)
            self.assertTrue(decoded.bered)


class TestX690PrefixedType(TestCase):
    def test_1(self):
        self.assertSequenceEqual(
            VisibleString("Jones").encode(),
            hexdec("1A054A6F6E6573"),
        )

    def test_2(self):
        self.assertSequenceEqual(
            VisibleString(
                "Jones",
                impl=tag_encode(3, klass=TagClassApplication),
            ).encode(),
            hexdec("43054A6F6E6573"),
        )

    def test_3(self):
        self.assertSequenceEqual(
            Any(
                VisibleString(
                    "Jones",
                    impl=tag_encode(3, klass=TagClassApplication),
                ),
                expl=tag_ctxc(2),
            ).encode(),
            hexdec("A20743054A6F6E6573"),
        )

    def test_4(self):
        self.assertSequenceEqual(
            OctetString(
                VisibleString(
                    "Jones",
                    impl=tag_encode(3, klass=TagClassApplication),
                ).encode(),
                impl=tag_encode(7, form=TagFormConstructed, klass=TagClassApplication),
            ).encode(),
            hexdec("670743054A6F6E6573"),
        )

    def test_5(self):
        self.assertSequenceEqual(
            VisibleString("Jones", impl=tag_ctxp(2)).encode(),
            hexdec("82054A6F6E6573"),
        )


class TestExplOOB(TestCase):
    def runTest(self):
        expl = tag_ctxc(123)
        raw = Integer(123).encode() + Integer(234).encode()
        raw = b"".join((expl, len_encode(len(raw)), raw))
        with self.assertRaisesRegex(DecodeError, "explicit tag out-of-bound"):
            Integer(expl=expl).decode(raw)
        Integer(expl=expl).decode(raw, ctx={"allow_expl_oob": True})


class TestPickleDifferentVersion(TestCase):
    def runTest(self):
        pickled = pickle_dumps(Integer(123), pickle_proto)
        import pyderasn
        version_orig = pyderasn.__version__
        pyderasn.__version__ += "different"
        with self.assertRaisesRegex(ValueError, "different PyDERASN version"):
            pickle_loads(pickled)
        pyderasn.__version__ = version_orig
        pickle_loads(pickled)


class TestCERSetOrdering(TestCase):
    def test_vectors(self):
        """Taken from X.690-201508
        """
        class B(Choice):
            schema = (
                ("c", Integer(impl=tag_ctxp(2))),
                ("d", Integer(impl=tag_ctxp(4))),
            )

        class F(Choice):
            schema = (
                ("g", Integer(impl=tag_ctxp(5))),
                ("h", Integer(impl=tag_ctxp(6))),
            )

        class I(Choice):
            schema = (
                ("j", Integer(impl=tag_ctxp(0))),
            )

        class E(Choice):
            schema = (
                ("f", F()),
                ("i", I()),
            )

        class A(Set):
            schema = (
                ("a", Integer(impl=tag_ctxp(3))),
                ("b", B(expl=tag_ctxc(1))),
                ("e", E()),
            )

        a = A((
            ("a", Integer(123)),
            ("b", B(("d", Integer(234)))),
            ("e", E(("f", F(("g", Integer(345)))))),
        ))
        order = sorted(a._values_for_encoding(), key=attrgetter("tag_order_cer"))
        self.assertSequenceEqual(
            [i.__class__.__name__ for i in order],
            ("E", "B", "Integer"),
        )
