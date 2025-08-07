"""COMPLI ASN.1:2008 compliance test suite

COMPLI is a collection of BER-encoded examples that must behave in
strictly defined way. All of them are to be valid ASN.1 encodings,
however some of them do not comply with X.690-201508, so PyDERASN
behaves differently in some tests. PyDERASN does not support REAL
values too.
"""

from os import path
from unittest import skip
from unittest import TestCase

from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import DecodeError
from pyderasn import Integer
from pyderasn import InvalidLength
from pyderasn import len_decode
from pyderasn import LenIndefForm
from pyderasn import NotEnoughData
from pyderasn import Null
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import tag_decode
from pyderasn import tag_strip


test_suite_path = path.join(
    path.dirname(path.abspath(__file__)),
    "compli_test_suite",
    "suite",
)


def load_tc(num):
    with open(path.join(test_suite_path, ("tc%d.ber" % num)), "rb") as fd:
        return fd.read()


class TestTestSuite(TestCase):
    def test_tc1(self):
        data = load_tc(1)
        tag_strip(data)
        tag_decode(data)

    def test_tc2(self):
        data = load_tc(2)
        with self.assertRaisesRegex(DecodeError, "unfinished tag"):
            tag_strip(data)

    def test_tc3(self):
        data = load_tc(3)
        t, _, _ = tag_strip(data)
        with self.assertRaises(NotEnoughData):
            OctetString(impl=t).decode(data)

    def test_tc4(self):
        data = load_tc(4)
        t, _, lv = tag_strip(data)
        with self.assertRaises(NotEnoughData):
            len_decode(lv)

    def test_tc5(self):
        data = load_tc(5)
        t, _, lv = tag_strip(data)
        with self.assertRaisesRegex(DecodeError, "long form instead of"):
            len_decode(lv)

    @skip("PyDERASN does not support REAL")
    def test_tc6(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc7(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc8(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc9(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc10(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc11(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc12(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc13(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc14(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc15(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc16(self):
        pass

    @skip("PyDERASN does not support REAL")
    def test_tc17(self):
        pass

    def test_tc18(self):
        data = load_tc(18)
        with self.assertRaisesRegex(DecodeError, "non normalized"):
            Integer().decode(data)

    def test_tc19(self):
        data = load_tc(19)
        with self.assertRaises(NotEnoughData):
            Integer().decode(data)

    def test_tc20(self):
        data = load_tc(20)
        Integer().decode(data)

    def test_tc21(self):
        data = load_tc(21)
        with self.assertRaisesRegex(DecodeError, "non normalized"):
            ObjectIdentifier().decode(data)
        ObjectIdentifier().decode(data, ctx={"bered": True})

    def test_tc22(self):
        data = load_tc(22)
        with self.assertRaisesRegex(DecodeError, "too huge value"):
            ObjectIdentifier().decode(data)

    def test_tc23(self):
        data = load_tc(23)
        with self.assertRaises(NotEnoughData):
            ObjectIdentifier().decode(data)

    def test_tc24(self):
        data = load_tc(24)
        ObjectIdentifier().decode(data)

    def test_tc25(self):
        # X.690-201508 8.2.1: The encoding of a boolean value shall be
        # primitive. The contents octets shall consist of a single octet.
        data = load_tc(25)
        with self.assertRaises(InvalidLength):
            Boolean().decode(data)
        with self.assertRaises(InvalidLength):
            Boolean().decode(data, ctx={"bered": True})

    def test_tc26(self):
        # X.690-201508 8.2.1: The encoding of a boolean value shall be
        # primitive. The contents octets shall consist of a single octet.
        data = load_tc(26)
        with self.assertRaises(InvalidLength):
            Boolean().decode(data)
        with self.assertRaises(InvalidLength):
            Boolean().decode(data, ctx={"bered": True})

    def test_tc27(self):
        data = load_tc(27)
        with self.assertRaises(InvalidLength):
            Boolean().decode(data)

    def test_tc28(self):
        data = load_tc(28)
        self.assertTrue(bool(Boolean().decode(data)[0]))

    def test_tc29(self):
        data = load_tc(29)
        self.assertFalse(bool(Boolean().decode(data)[0]))

    def test_tc30(self):
        data = load_tc(30)
        with self.assertRaises(InvalidLength):
            Null().decode(data)

    def test_tc31(self):
        data = load_tc(31)
        with self.assertRaises(InvalidLength):
            Null().decode(data)

    def test_tc32(self):
        data = load_tc(32)
        Null().decode(data)

    def test_tc33(self):
        data = load_tc(33)
        with self.assertRaisesRegex(DecodeError, "too big pad"):
            BitString().decode(data)
        with self.assertRaisesRegex(DecodeError, "too big pad"):
            BitString().decode(data, ctx={"bered": True})

    def test_tc34(self):
        data = load_tc(34)
        with self.assertRaises(NotEnoughData):
            BitString().decode(data)

    def test_tc35(self):
        data = load_tc(35)
        with self.assertRaisesRegex(DecodeError, "expected BitString encoded chunk"):
            BitString().decode(data, ctx={"bered": True})

    def test_tc36(self):
        data = load_tc(36)
        with self.assertRaisesRegex(DecodeError, "invalid pad"):
            BitString().decode(data, ctx={"bered": True})

    def test_tc37(self):
        # X.690-201508 8.6.4: To encode a bitstring value in this way,
        # it is segmented. Each segment shall consist of a series of
        # consecutive bits of the value, and with the possible exception
        # of the last, shall contain a number of bits which is a
        # multiple of eight.
        data = load_tc(37)
        with self.assertRaisesRegex(DecodeError, "invalid pad"):
            BitString().decode(data, ctx={"bered": True})

    def test_tc38(self):
        data = load_tc(38)
        BitString().decode(data, ctx={"bered": True})

    def test_tc39(self):
        # X.690-201508 8.6.2: The contents octets for the primitive
        # encoding shall contain an initial octet followed by zero, one
        # or more subsequent octets.
        # X.690-201508 8.6.2.3: If the bitstring is empty, there shall
        # be no subsequent octets, and the initial octet shall be zero.
        data = load_tc(39)
        with self.assertRaises(NotEnoughData):
            BitString().decode(data, ctx={"bered": True})

    def test_tc40(self):
        # X.690-201508 8.6.2: The contents octets for the primitive
        # encoding shall contain an initial octet followed by zero, one
        # or more subsequent octets.
        # X.690-201508 8.6.2.3: If the bitstring is empty, there shall
        # be no subsequent octets, and the initial octet shall be zero.
        data = load_tc(40)
        with self.assertRaises(NotEnoughData):
            BitString().decode(data, ctx={"bered": True})

    def test_tc41(self):
        data = load_tc(41)
        with self.assertRaisesRegex(DecodeError, "expected OctetString encoded chunk"):
            OctetString().decode(data, ctx={"bered": True})

    def test_tc42(self):
        data = load_tc(42)
        with self.assertRaises(NotEnoughData):
            OctetString().decode(data, ctx={"bered": True})

    def test_tc43(self):
        data = load_tc(43)
        with self.assertRaises(NotEnoughData):
            OctetString().decode(data, ctx={"bered": True})

    def test_tc44(self):
        data = load_tc(44)
        OctetString().decode(data)

    def test_tc45(self):
        data = load_tc(45)
        OctetString().decode(data, ctx={"bered": True})

    def test_tc46(self):
        data = load_tc(46)
        with self.assertRaises(LenIndefForm):
            BitString().decode(data, ctx={"bered": True})

    def test_tc47(self):
        data = load_tc(47)
        with self.assertRaisesRegex(DecodeError, "expected BitString encoded chunk"):
            BitString().decode(data, ctx={"bered": True})

    def test_tc48(self):
        data = load_tc(48)
        with self.assertRaisesRegex(DecodeError, "too big pad"):
            BitString().decode(data, ctx={"bered": True})
