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

from hashlib import sha512
from io import BytesIO
from io import open as io_open
from os import environ
from os import remove
from os import urandom
from subprocess import call
from sys import getsizeof
from tempfile import NamedTemporaryFile
from time import time
from unittest import skipIf
from unittest import TestCase

from hypothesis import given
from hypothesis import settings
from hypothesis.strategies import integers

from pyderasn import agg_octet_string
from pyderasn import Any
from pyderasn import Choice
from pyderasn import encode_cer
from pyderasn import file_mmaped
from pyderasn import Integer
from pyderasn import ObjectIdentifier
from pyderasn import OctetString
from pyderasn import Sequence
from pyderasn import SetOf
from pyderasn import tag_ctxc
from pyderasn import tag_ctxp
from tests.test_crts import AlgorithmIdentifier
from tests.test_crts import Certificate
from tests.test_crts import SubjectKeyIdentifier


class CMSVersion(Integer):
    schema = (
        ("v0", 0),
        ("v1", 1),
        ("v2", 2),
        ("v3", 3),
        ("v4", 4),
        ("v5", 5),
    )


class AttributeValue(Any):
    pass


class AttributeValues(SetOf):
    schema = AttributeValue()


class Attribute(Sequence):
    schema = (
        ("attrType", ObjectIdentifier()),
        ("attrValues", AttributeValues()),
    )


class SignatureAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class SignedAttributes(SetOf):
    schema = Attribute()
    bounds = (1, float("+inf"))
    der_forced = True


class SignerIdentifier(Choice):
    schema = (
        # ("issuerAndSerialNumber", IssuerAndSerialNumber()),
        ("subjectKeyIdentifier", SubjectKeyIdentifier(impl=tag_ctxp(0))),
    )


class DigestAlgorithmIdentifiers(SetOf):
    schema = AlgorithmIdentifier()


class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class SignatureValue(OctetString):
    pass


class SignerInfo(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("sid", SignerIdentifier()),
        ("digestAlgorithm", DigestAlgorithmIdentifier()),
        ("signedAttrs", SignedAttributes(impl=tag_ctxc(0), optional=True)),
        ("signatureAlgorithm", SignatureAlgorithmIdentifier()),
        ("signature", SignatureValue()),
        # ("unsignedAttrs", UnsignedAttributes(impl=tag_ctxc(1), optional=True)),
    )


class SignerInfos(SetOf):
    schema = SignerInfo()


class ContentType(ObjectIdentifier):
    pass


class EncapsulatedContentInfo(Sequence):
    schema = (
        ("eContentType", ContentType()),
        ("eContent", OctetString(expl=tag_ctxc(0), optional=True)),
    )


class CertificateChoices(Choice):
    schema = (
        ('certificate', Certificate()),
        # ...
    )


class CertificateSet(SetOf):
    schema = CertificateChoices()


class SignedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("digestAlgorithms", DigestAlgorithmIdentifiers()),
        ("encapContentInfo", EncapsulatedContentInfo()),
        ("certificates", CertificateSet(impl=tag_ctxc(0), optional=True)),
        # ("crls", RevocationInfoChoices(impl=tag_ctxc(1), optional=True)),
        ("signerInfos", SignerInfos()),
    )


class ContentInfo(Sequence):
    schema = (
        ("contentType", ContentType()),
        ("content", Any(expl=tag_ctxc(0))),
    )


id_signedData = ObjectIdentifier("1.2.840.113549.1.7.2")
id_sha512 = ObjectIdentifier("2.16.840.1.101.3.4.2.3")
id_data = ObjectIdentifier("1.2.840.113549.1.7.1")
id_ecdsa_with_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
id_pkcs9_at_contentType = ObjectIdentifier("1.2.840.113549.1.9.3")
id_pkcs9_at_messageDigest = ObjectIdentifier("1.2.840.113549.1.9.4")
id_ce_subjectKeyIdentifier = ObjectIdentifier("2.5.29.14")
ai_sha512 = AlgorithmIdentifier((("algorithm", id_sha512),))

openssl_cms_exists = call("openssl cms -help 2>/dev/null", shell=True) == 0

@skipIf(not openssl_cms_exists, "openssl cms command not found")
class TestSignedDataCERWithOpenSSL(TestCase):
    def tmpfile(self):
        tmp = NamedTemporaryFile(delete=False)
        tmp.close()
        self.addCleanup(lambda: remove(tmp.name))
        return tmp.name

    def keypair(self):
        key_path = self.tmpfile()
        self.assertEqual(0, call(
            "openssl ecparam -name secp521r1 -genkey -out " + key_path,
            shell=True,
        ))
        cert_path = self.tmpfile()
        self.assertEqual(0, call(" ".join((
            "openssl req -x509 -new",
            ("-key " + key_path),
            ("-outform PEM -out " + cert_path),
            "-nodes -subj /CN=pyderasntest",
        )), shell=True))
        cert_der_path = self.tmpfile()
        self.assertEqual(0, call(" ".join((
            "openssl x509",
            "-inform PEM -in " + cert_path,
            "-outform DER -out " + cert_der_path,
        )), shell=True))
        self.assertEqual(0, call("cat %s >> %s" % (key_path, cert_path), shell=True))
        with open(cert_der_path, "rb") as fd:
            cert = Certificate().decod(fd.read())
        for ext in cert["tbsCertificate"]["extensions"]:
            if ext["extnID"] == id_ce_subjectKeyIdentifier:
                skid = SubjectKeyIdentifier().decod(bytes(ext["extnValue"]))
        return key_path, cert_path, cert, skid

    def sign(self, signed_attrs, key_path):
        input_path = self.tmpfile()
        with open(input_path, "wb") as fd:
            fd.write(encode_cer(signed_attrs))
        signature_path = self.tmpfile()
        self.assertEqual(0, call(" ".join((
            "openssl dgst -sha512",
            ("-sign " + key_path),
            "-binary", input_path,
            ("> " + signature_path),
        )), shell=True))
        with open(signature_path, "rb") as fd:
            signature = fd.read()
        return signature

    def verify(self, cert_path, cms_path):
        self.assertEqual(0, call(" ".join((
            "openssl cms -verify",
            ("-inform DER -in " + cms_path),
            "-signer %s -CAfile %s" % (cert_path, cert_path),
            "-out /dev/null 2>/dev/null",
        )), shell=True))

    @settings(deadline=None)
    @given(integers(min_value=1000, max_value=5000))
    def test_simple(self, data_len):
        key_path, cert_path, cert, skid = self.keypair()
        data = urandom(data_len)
        eci = EncapsulatedContentInfo((
            ("eContentType", ContentType(id_data)),
            ("eContent", OctetString(data)),
        ))
        signed_attrs = SignedAttributes([
            Attribute((
                ("attrType", id_pkcs9_at_contentType),
                ("attrValues", AttributeValues([AttributeValue(id_data)])),
            )),
            Attribute((
                ("attrType", id_pkcs9_at_messageDigest),
                ("attrValues", AttributeValues([
                    AttributeValue(OctetString(
                        sha512(bytes(eci["eContent"])).digest()
                    )),
                ])),
            )),
        ])
        signature = self.sign(signed_attrs, key_path)
        ci = ContentInfo((
            ("contentType", ContentType(id_signedData)),
            ("content", Any((SignedData((
                ("version", CMSVersion("v3")),
                ("digestAlgorithms", DigestAlgorithmIdentifiers([ai_sha512])),
                ("encapContentInfo", eci),
                ("certificates", CertificateSet([
                    CertificateChoices(("certificate", cert)),
                ])),
                ("signerInfos", SignerInfos([SignerInfo((
                    ("version", CMSVersion("v3")),
                    ("sid", SignerIdentifier(("subjectKeyIdentifier", skid))),
                    ("digestAlgorithm", DigestAlgorithmIdentifier(ai_sha512)),
                    ("signedAttrs", signed_attrs),
                    ("signatureAlgorithm", SignatureAlgorithmIdentifier((
                        ("algorithm", id_ecdsa_with_SHA512),
                    ))),
                    ("signature", SignatureValue(signature)),
                ))])),
            ))))),
        ))
        cms_path = self.tmpfile()
        _, state = ci.encode1st()
        with io_open(cms_path, "wb") as fd:
            ci.encode2nd(fd.write, iter(state))
        self.verify(cert_path, cms_path)
        with io_open(cms_path, "wb") as fd:
            ci.encode_cer(fd.write)
        self.verify(cert_path, cms_path)
        fd = open(cms_path, "rb")
        raw = file_mmaped(fd)
        ctx = {"bered": True}
        for decode_path, obj, _ in ContentInfo().decode_evgen(raw, ctx=ctx):
            if decode_path == ("content",):
                break
        evgens = SignedData().decode_evgen(raw[obj.offset:], offset=obj.offset, ctx=ctx)
        buf = BytesIO()
        agg_octet_string(evgens, ("encapContentInfo", "eContent"), raw, buf.write)
        self.assertSequenceEqual(buf.getvalue(), data)
        fd.close()

    def create_huge_file(self):
        rnd = urandom(1<<20)
        data_path = self.tmpfile()
        start = time()
        with open(data_path, "wb") as fd:
            for _ in range(int(environ.get("PYDERASN_TEST_CMS_HUGE"))):
                # dgst.update(rnd)
                fd.write(rnd)
        print("data file written", time() - start)
        return file_mmaped(open(data_path, "rb"))

    @skipIf("PYDERASN_TEST_CMS_HUGE" not in environ, "PYDERASN_TEST_CMS_HUGE is not set")
    def test_huge_cer(self):
        """Huge CMS test

        Environment variable PYDERASN_TEST_CMS_HUGE tells how many MiBs
        data to sign. Pay attention that openssl cms is unable to do
        stream verification and eats huge amounts (several times more,
        than CMS itself) of memory.
        """
        data_raw = self.create_huge_file()
        key_path, cert_path, cert, skid = self.keypair()
        from sys import getallocatedblocks
        mem_start = getallocatedblocks()
        start = time()
        eci = EncapsulatedContentInfo((
            ("eContentType", ContentType(id_data)),
            ("eContent", OctetString(data_raw)),
        ))
        eci_path = self.tmpfile()
        with open(eci_path, "wb") as fd:
            OctetString(eci["eContent"]).encode_cer(fd.write)
        print("ECI file written", time() - start)
        eci_fd = open(eci_path, "rb")
        eci_raw = file_mmaped(eci_fd)

        start = time()
        dgst = sha512()
        def hasher(data):
            dgst.update(data)
            return len(data)
        evgens = OctetString().decode_evgen(eci_raw, ctx={"bered": True})
        agg_octet_string(evgens, (), eci_raw, hasher)
        dgst = dgst.digest()
        print("digest calculated", time() - start)

        signed_attrs = SignedAttributes([
            Attribute((
                ("attrType", id_pkcs9_at_contentType),
                ("attrValues", AttributeValues([AttributeValue(id_data)])),
            )),
            Attribute((
                ("attrType", id_pkcs9_at_messageDigest),
                ("attrValues", AttributeValues([AttributeValue(OctetString(dgst))])),
            )),
        ])
        signature = self.sign(signed_attrs, key_path)

        self.assertLess(getallocatedblocks(), mem_start * 2)
        start = time()
        ci = ContentInfo((
            ("contentType", ContentType(id_signedData)),
            ("content", Any((SignedData((
                ("version", CMSVersion("v3")),
                ("digestAlgorithms", DigestAlgorithmIdentifiers([ai_sha512])),
                ("encapContentInfo", eci),
                ("certificates", CertificateSet([
                    CertificateChoices(("certificate", cert)),
                ])),
                ("signerInfos", SignerInfos([SignerInfo((
                    ("version", CMSVersion("v3")),
                    ("sid", SignerIdentifier(("subjectKeyIdentifier", skid))),
                    ("digestAlgorithm", DigestAlgorithmIdentifier(ai_sha512)),
                    ("signedAttrs", signed_attrs),
                    ("signatureAlgorithm", SignatureAlgorithmIdentifier((
                        ("algorithm", id_ecdsa_with_SHA512),
                    ))),
                    ("signature", SignatureValue(signature)),
                ))])),
            ))))),
        ))
        cms_path = self.tmpfile()
        with io_open(cms_path, "wb") as fd:
            ci.encode_cer(fd.write)
        print("CMS written", time() - start)
        self.verify(cert_path, cms_path)
        eci_fd.close()

    @skipIf("PYDERASN_TEST_CMS_HUGE" not in environ, "PYDERASN_TEST_CMS_HUGE is not set")
    def test_huge_der_2pass(self):
        """Same test as above, but 2pass DER encoder and just signature verification
        """
        data_raw = self.create_huge_file()
        key_path, cert_path, cert, skid = self.keypair()
        from sys import getallocatedblocks
        mem_start = getallocatedblocks()
        dgst = sha512(data_raw).digest()
        start = time()
        eci = EncapsulatedContentInfo((
            ("eContentType", ContentType(id_data)),
            ("eContent", OctetString(data_raw)),
        ))
        signed_attrs = SignedAttributes([
            Attribute((
                ("attrType", id_pkcs9_at_contentType),
                ("attrValues", AttributeValues([AttributeValue(id_data)])),
            )),
            Attribute((
                ("attrType", id_pkcs9_at_messageDigest),
                ("attrValues", AttributeValues([AttributeValue(OctetString(dgst))])),
            )),
        ])
        signature = self.sign(signed_attrs, key_path)
        self.assertLess(getallocatedblocks(), mem_start * 2)
        start = time()
        ci = ContentInfo((
            ("contentType", ContentType(id_signedData)),
            ("content", Any((SignedData((
                ("version", CMSVersion("v3")),
                ("digestAlgorithms", DigestAlgorithmIdentifiers([ai_sha512])),
                ("encapContentInfo", eci),
                ("certificates", CertificateSet([
                    CertificateChoices(("certificate", cert)),
                ])),
                ("signerInfos", SignerInfos([SignerInfo((
                    ("version", CMSVersion("v3")),
                    ("sid", SignerIdentifier(("subjectKeyIdentifier", skid))),
                    ("digestAlgorithm", DigestAlgorithmIdentifier(ai_sha512)),
                    ("signedAttrs", signed_attrs),
                    ("signatureAlgorithm", SignatureAlgorithmIdentifier((
                        ("algorithm", id_ecdsa_with_SHA512),
                    ))),
                    ("signature", SignatureValue(signature)),
                ))])),
            ))))),
        ))
        _, state = ci.encode1st()
        print("2pass state size", getsizeof(state))
        cms_path = self.tmpfile()
        with io_open(cms_path, "wb") as fd:
            ci.encode2nd(fd.write, iter(state))
        print("CMS written", time() - start)
        self.assertLess(getallocatedblocks(), mem_start * 2)
        self.verify(cert_path, cms_path)
