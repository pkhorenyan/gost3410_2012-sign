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
from datetime import datetime
from pickle import dumps as pickle_dumps
from pickle import HIGHEST_PROTOCOL as pickle_proto
from pickle import loads as pickle_loads
from unittest import TestCase

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import Choice
from pyderasn import DecodeError
from pyderasn import encode_cer
from pyderasn import GeneralizedTime
from pyderasn import hexdec
from pyderasn import IA5String
from pyderasn import Integer
from pyderasn import Null
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import pprint
from pyderasn import PrintableString
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp
from pyderasn import TeletexString
from pyderasn import UTCTime
from pyderasn import UTF8String


name2oid = {
    "id-rsaEncryption": ObjectIdentifier("1.2.840.113549.1.1.1"),
    "id-sha1WithRSAEncryption": ObjectIdentifier("1.2.840.113549.1.1.5"),
    "id-emailAddress": ObjectIdentifier("1.2.840.113549.1.9.1"),
    "id-ce-subjectKeyIdentifier": ObjectIdentifier("2.5.29.14"),
    "id-ce-keyUsage": ObjectIdentifier("2.5.29.15"),
    "id-ce-subjectAltName": ObjectIdentifier("2.5.29.17"),
    "id-ce-issuerAltName": ObjectIdentifier("2.5.29.18"),
    "id-ce-basicConstraints": ObjectIdentifier("2.5.29.19"),
    "id-ce-cRLDistributionPoints": ObjectIdentifier("2.5.29.31"),
    "id-ce-authorityKeyIdentifier": ObjectIdentifier("2.5.29.35"),
    "id-ce-extKeyUsage": ObjectIdentifier("2.5.29.37"),
    "id-at-commonName": ObjectIdentifier("2.5.4.3"),
    "id-at-countryName": ObjectIdentifier("2.5.4.6"),
    "id-at-localityName": ObjectIdentifier("2.5.4.7"),
    "id-at-stateOrProvinceName": ObjectIdentifier("2.5.4.8"),
    "id-at-organizationName": ObjectIdentifier("2.5.4.10"),
    "id-at-organizationalUnitName": ObjectIdentifier("2.5.4.11"),
}
stroid2name = {str(oid): name for name, oid in name2oid.items()}


class Version(Integer):
    schema = (
        ("v1", 0),
        ("v2", 1),
        ("v3", 2),
    )


class CertificateSerialNumber(Integer):
    pass


class AlgorithmIdentifier(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier()),
        ("parameters", Any(optional=True)),
    )


class AttributeType(ObjectIdentifier):
    pass


class AttributeValue(Any):
    pass


class OrganizationName(Choice):
    schema = (
        ("printableString", PrintableString()),
        ("teletexString", TeletexString()),
    )


class CommonName(Choice):
    schema = (
        ("printableString", PrintableString()),
        ("utf8String", UTF8String()),
    )


class AttributeTypeAndValue(Sequence):
    schema = (
        ("type", AttributeType(defines=((("value",), {
            name2oid["id-at-countryName"]: PrintableString(),
            name2oid["id-at-localityName"]: PrintableString(),
            name2oid["id-at-stateOrProvinceName"]: PrintableString(),
            name2oid["id-at-organizationName"]: OrganizationName(),
            name2oid["id-at-commonName"]: CommonName(),
        }),))),
        ("value", AttributeValue()),
    )


class RelativeDistinguishedName(SetOf):
    schema = AttributeTypeAndValue()
    bounds = (1, float("+inf"))


class RDNSequence(SequenceOf):
    schema = RelativeDistinguishedName()


class Name(Choice):
    schema = (
        ("rdnSequence", RDNSequence()),
    )


class Time(Choice):
    schema = (
        ("utcTime", UTCTime()),
        ("generalTime", GeneralizedTime()),
    )


class Validity(Sequence):
    schema = (
        ("notBefore", Time()),
        ("notAfter", Time()),
    )


class SubjectPublicKeyInfo(Sequence):
    schema = (
        ("algorithm", AlgorithmIdentifier()),
        ("subjectPublicKey", BitString()),
    )


class UniqueIdentifier(BitString):
    pass


class KeyIdentifier(OctetString):
    pass


class SubjectKeyIdentifier(KeyIdentifier):
    pass


class Extension(Sequence):
    schema = (
        ("extnID", ObjectIdentifier()),
        ("critical", Boolean(default=False)),
        ("extnValue", OctetString()),
    )


class Extensions(SequenceOf):
    schema = Extension()
    bounds = (1, float("+inf"))


class TBSCertificate(Sequence):
    schema = (
        ("version", Version(expl=tag_ctxc(0), default="v1")),
        ("serialNumber", CertificateSerialNumber()),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("validity", Validity()),
        ("subject", Name()),
        ("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
        ("issuerUniqueID", UniqueIdentifier(impl=tag_ctxp(1), optional=True)),
        ("subjectUniqueID", UniqueIdentifier(impl=tag_ctxp(2), optional=True)),
        ("extensions", Extensions(expl=tag_ctxc(3), optional=True)),
    )


class Certificate(Sequence):
    schema = (
        ("tbsCertificate", TBSCertificate()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )
    der_forced = True


class TestGoSelfSignedVector(TestCase):
    def runTest(self):
        raw = hexdec("".join((
            "30820218308201c20209008cc3379210ec2c98300d06092a864886f70d0101050",
            "500308192310b3009060355040613025858311330110603550408130a536f6d65",
            "2d5374617465310d300b06035504071304436974793121301f060355040a13184",
            "96e7465726e6574205769646769747320507479204c7464311a30180603550403",
            "131166616c73652e6578616d706c652e636f6d3120301e06092a864886f70d010",
            "901161166616c7365406578616d706c652e636f6d301e170d3039313030383030",
            "323535335a170d3130313030383030323535335a308192310b300906035504061",
            "3025858311330110603550408130a536f6d652d5374617465310d300b06035504",
            "071304436974793121301f060355040a1318496e7465726e65742057696467697",
            "47320507479204c7464311a30180603550403131166616c73652e6578616d706c",
            "652e636f6d3120301e06092a864886f70d010901161166616c7365406578616d7",
            "06c652e636f6d305c300d06092a864886f70d0101010500034b003048024100cd",
            "b7639c3278f006aa277f6eaf42902b592d8cbcbe38a1c92ba4695a331b1deadea",
            "dd8e9a5c27e8c4c2fd0a8889657722a4f2af7589cf2c77045dc8fdeec357d0203",
            "010001300d06092a864886f70d0101050500034100a67b06ec5ece92772ca413c",
            "ba3ca12568fdc6c7b4511cd40a7f659980402df2b998bb9a4a8cbeb34c0f0a78c",
            "f8d91ede14a5ed76bf116fe360aafa8821490435",
        )))
        crt = Certificate().decod(raw, ctx={"keep_memoryview": True})
        tbs = crt["tbsCertificate"]
        self.assertEqual(tbs["version"], 0)
        self.assertFalse(tbs["version"].decoded)
        self.assertNotIn("version", tbs)
        self.assertEqual(tbs["serialNumber"], 10143011886257155224)

        def assert_raw_equals(obj, expect):
            self.assertTrue(obj.decoded)
            self.assertSequenceEqual(
                raw[obj.offset:obj.offset + obj.tlvlen],
                expect.encode(),
            )
        assert_raw_equals(tbs["serialNumber"], Integer(10143011886257155224))
        algo_id = AlgorithmIdentifier((
            ("algorithm", name2oid["id-sha1WithRSAEncryption"]),
            ("parameters", Any(Null())),
        ))
        self.assertEqual(tbs["signature"], algo_id)
        assert_raw_equals(tbs["signature"], algo_id)
        rdnSeq = RDNSequence()
        for oid, klass, text in (
                ("2.5.4.6", PrintableString, "XX"),
                ("2.5.4.8", PrintableString, "Some-State"),
                ("2.5.4.7", PrintableString, "City"),
                ("2.5.4.10", PrintableString, "Internet Widgits Pty Ltd"),
                ("2.5.4.3", PrintableString, "false.example.com"),
                ("1.2.840.113549.1.9.1", IA5String, "false@example.com"),
        ):
            rdnSeq.append(
                RelativeDistinguishedName((
                    AttributeTypeAndValue((
                        ("type", AttributeType(oid)),
                        ("value", AttributeValue(klass(text))),
                    )),
                ))
            )
        issuer = Name(("rdnSequence", rdnSeq))
        self.assertEqual(tbs["issuer"], issuer)
        assert_raw_equals(tbs["issuer"], issuer)
        validity = Validity((
            ("notBefore", Time(
                ("utcTime", UTCTime(datetime(2009, 10, 8, 0, 25, 53)))
            )),
            ("notAfter", Time(
                ("utcTime", UTCTime(datetime(2010, 10, 8, 0, 25, 53)))
            )),
        ))
        self.assertEqual(tbs["validity"], validity)
        assert_raw_equals(tbs["validity"], validity)
        self.assertEqual(tbs["subject"], issuer)
        assert_raw_equals(tbs["subject"], issuer)
        spki = SubjectPublicKeyInfo()
        algo_id["algorithm"] = name2oid["id-rsaEncryption"]
        spki["algorithm"] = algo_id
        spki["subjectPublicKey"] = BitString(hexdec("".join((
            "3048024100cdb7639c3278f006aa277f6eaf42902b592d8cbcbe38a1c92ba4695",
            "a331b1deadeadd8e9a5c27e8c4c2fd0a8889657722a4f2af7589cf2c77045dc8f",
            "deec357d0203010001",
        ))))
        self.assertEqual(tbs["subjectPublicKeyInfo"], spki)
        assert_raw_equals(tbs["subjectPublicKeyInfo"], spki)
        self.assertNotIn("issuerUniqueID", tbs)
        self.assertNotIn("subjectUniqueID", tbs)
        self.assertNotIn("extensions", tbs)
        algo_id["algorithm"] = name2oid["id-sha1WithRSAEncryption"]
        self.assertEqual(crt["signatureAlgorithm"], algo_id)
        self.assertEqual(crt["signatureValue"], BitString(hexdec("".join((
            "a67b06ec5ece92772ca413cba3ca12568fdc6c7b4511cd40a7f659980402df2b",
            "998bb9a4a8cbeb34c0f0a78cf8d91ede14a5ed76bf116fe360aafa8821490435",
        )))))
        self.assertSequenceEqual(crt.encode(), raw)
        crt = Certificate().decod(raw)
        pprint(crt)
        repr(crt)
        pickle_loads(pickle_dumps(crt, pickle_proto))

        tbs = TBSCertificate()
        tbs["serialNumber"] = CertificateSerialNumber(10143011886257155224)

        sign_algo_id = AlgorithmIdentifier((
            ("algorithm", name2oid["id-sha1WithRSAEncryption"]),
            ("parameters", Any(Null())),
        ))
        tbs["signature"] = sign_algo_id

        rdnSeq = RDNSequence()
        for oid, klass, text in (
                ("2.5.4.6", PrintableString, "XX"),
                ("2.5.4.8", PrintableString, "Some-State"),
                ("2.5.4.7", PrintableString, "City"),
                ("2.5.4.10", PrintableString, "Internet Widgits Pty Ltd"),
                ("2.5.4.3", PrintableString, "false.example.com"),
                ("1.2.840.113549.1.9.1", IA5String, "false@example.com"),
        ):
            rdnSeq.append(
                RelativeDistinguishedName((
                    AttributeTypeAndValue((
                        ("type", AttributeType(oid)),
                        ("value", AttributeValue(klass(text))),
                    )),
                ))
            )
        issuer = Name()
        issuer["rdnSequence"] = rdnSeq
        tbs["issuer"] = issuer
        tbs["subject"] = issuer

        validity = Validity((
            ("notBefore", Time(
                ("utcTime", UTCTime(datetime(2009, 10, 8, 0, 25, 53)),),
            )),
            ("notAfter", Time(
                ("utcTime", UTCTime(datetime(2010, 10, 8, 0, 25, 53)),),
            )),
        ))
        tbs["validity"] = validity

        spki = SubjectPublicKeyInfo()
        spki_algo_id = copy(sign_algo_id)
        spki_algo_id["algorithm"] = name2oid["id-rsaEncryption"]
        spki["algorithm"] = spki_algo_id
        spki["subjectPublicKey"] = BitString(hexdec("".join((
            "3048024100cdb7639c3278f006aa277f6eaf42902b592d8cbcbe38a1c92ba4695",
            "a331b1deadeadd8e9a5c27e8c4c2fd0a8889657722a4f2af7589cf2c77045dc8f",
            "deec357d0203010001",
        ))))
        tbs["subjectPublicKeyInfo"] = spki

        crt = Certificate()
        crt["tbsCertificate"] = tbs
        crt["signatureAlgorithm"] = sign_algo_id
        crt["signatureValue"] = BitString(hexdec("".join((
            "a67b06ec5ece92772ca413cba3ca12568fdc6c7b4511cd40a7f659980402df2b",
            "998bb9a4a8cbeb34c0f0a78cf8d91ede14a5ed76bf116fe360aafa8821490435",
        ))))
        self.assertSequenceEqual(crt.encode(), raw)
        self.assertEqual(
            Certificate().decod(encode_cer(crt), ctx={"bered": True}),
            crt,
        )


class TestGoPayPalVector(TestCase):
    """PayPal certificate with "www.paypal.com\x00ssl.secureconnection.cc" name
    """
    def runTest(self):
        raw = hexdec("".join((
            "30820644308205ada003020102020300f09b300d06092a864886f70d010105050",
            "030820112310b3009060355040613024553311230100603550408130942617263",
            "656c6f6e61311230100603550407130942617263656c6f6e61312930270603550",
            "40a13204950532043657274696669636174696f6e20417574686f726974792073",
            "2e6c2e312e302c060355040a142567656e6572616c4069707363612e636f6d204",
            "32e492e462e2020422d423632323130363935312e302c060355040b1325697073",
            "434120434c41534541312043657274696669636174696f6e20417574686f72697",
            "479312e302c06035504031325697073434120434c415345413120436572746966",
            "69636174696f6e20417574686f726974793120301e06092a864886f70d0109011",
            "61167656e6572616c4069707363612e636f6d301e170d30393032323432333034",
            "31375a170d3131303232343233303431375a308194310b3009060355040613025",
            "553311330110603550408130a43616c69666f726e696131163014060355040713",
            "0d53616e204672616e636973636f3111300f060355040a1308536563757269747",
            "931143012060355040b130b53656375726520556e6974312f302d060355040313",
            "267777772e70617970616c2e636f6d0073736c2e736563757265636f6e6e65637",
            "4696f6e2e636330819f300d06092a864886f70d010101050003818d0030818902",
            "818100d269fa6f3a00b4211bc8b102d73f19b2c46db454f88b8accdb72c29e3c6",
            "0b9c6913d82b77d99ffd12984c173539c82ddfc248c77d541f3e81e42a1ad2d9e",
            "ff5b1026ce9d571773162338c8d6f1baa3965b16674a4f73973a4d14a4f4e23f8",
            "b058342d1d0dc2f7ae5b610b211c0dc212a90ffae97715a4981ac40f33bb859b2",
            "4f0203010001a38203213082031d30090603551d1304023000301106096086480",
            "186f8420101040403020640300b0603551d0f0404030203f830130603551d2504",
            "0c300a06082b06010505070301301d0603551d0e04160414618f61344355147f2",
            "709ce4c8bea9b7b1925bc6e301f0603551d230418301680140e0760d439c91b5b",
            "5d907b23c8d2349d4a9a463930090603551d1104023000301c0603551d1204153",
            "013811167656e6572616c4069707363612e636f6d307206096086480186f84201",
            "0d046516634f7267616e697a6174696f6e20496e666f726d6174696f6e204e4f5",
            "42056414c4944415445442e20434c415345413120536572766572204365727469",
            "666963617465206973737565642062792068747470733a2f2f7777772e6970736",
            "3612e636f6d2f302f06096086480186f84201020422162068747470733a2f2f77",
            "77772e69707363612e636f6d2f6970736361323030322f304306096086480186f",
            "84201040436163468747470733a2f2f7777772e69707363612e636f6d2f697073",
            "6361323030322f697073636132303032434c41534541312e63726c30460609608",
            "6480186f84201030439163768747470733a2f2f7777772e69707363612e636f6d",
            "2f6970736361323030322f7265766f636174696f6e434c41534541312e68746d6",
            "c3f304306096086480186f84201070436163468747470733a2f2f7777772e6970",
            "7363612e636f6d2f6970736361323030322f72656e6577616c434c41534541312",
            "e68746d6c3f304106096086480186f84201080434163268747470733a2f2f7777",
            "772e69707363612e636f6d2f6970736361323030322f706f6c696379434c41534",
            "541312e68746d6c3081830603551d1f047c307a3039a037a0358633687474703a",
            "2f2f7777772e69707363612e636f6d2f6970736361323030322f6970736361323",
            "03032434c41534541312e63726c303da03ba0398637687474703a2f2f77777762",
            "61636b2e69707363612e636f6d2f6970736361323030322f69707363613230303",
            "2434c41534541312e63726c303206082b0601050507010104263024302206082b",
            "060105050730018616687474703a2f2f6f6373702e69707363612e636f6d2f300",
            "d06092a864886f70d01010505000381810068ee799797dd3bef166a06f2149a6e",
            "cd9e12f7aa8310bdd17c98fac7aed40e2c9e38059d5260a9990a81b498901daeb",
            "b4ad7b9dc889e3778415bf782a5f2ba41255a901a1e4538a1525875942644fb20",
            "07ba44cce54a2d723f9847f626dc054605076321ab469b9c78d5545b3d0c1ec86",
            "48cb55023826fdbb8221c439607a8bb",
        )))
        with self.assertRaisesRegex(DecodeError, "alphabet value"):
            crt = Certificate().decod(raw)
