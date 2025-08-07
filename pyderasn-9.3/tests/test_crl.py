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
"""CRL related schemas, just to test the performance with them
"""

from io import BytesIO
from os.path import exists
from sys import getsizeof
from time import time
from unittest import skipIf
from unittest import TestCase

from pyderasn import BitString
from pyderasn import encode_cer
from pyderasn import file_mmaped
from pyderasn import Sequence
from pyderasn import SequenceOf
from pyderasn import tag_ctxc

from tests.test_crts import AlgorithmIdentifier
from tests.test_crts import CertificateSerialNumber
from tests.test_crts import Extensions
from tests.test_crts import Name
from tests.test_crts import Time
from tests.test_crts import Version


class RevokedCertificate(Sequence):
    schema = (
        ("userCertificate", CertificateSerialNumber()),
        ("revocationDate", Time()),
        ("crlEntryExtensions", Extensions(optional=True)),
    )


class RevokedCertificates(SequenceOf):
    schema = RevokedCertificate()


class TBSCertList(Sequence):
    schema = (
        ("version", Version(optional=True)),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("thisUpdate", Time()),
        ("nextUpdate", Time(optional=True)),
        ("revokedCertificates", RevokedCertificates(optional=True)),
        ("crlExtensions", Extensions(expl=tag_ctxc(0), optional=True)),
    )


class CertificateList(Sequence):
    schema = (
        ("tbsCertList", TBSCertList()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )


CRL_PATH = "revoke.crl"


@skipIf(not exists(CRL_PATH), "CACert's revoke.crl not found")
class TestCACert(TestCase):
    def test_cer_and_2pass(self):
        with open(CRL_PATH, "rb") as fd:
            raw = fd.read()
        print("DER read")
        start = time()
        crl1 = CertificateList().decod(raw)
        print("DER decoded", time() - start)
        start = time()
        der_raw = crl1.encode()
        print("DER encoded", time() - start)
        self.assertSequenceEqual(der_raw, raw)
        buf = BytesIO()
        start = time()
        _, state = crl1.encode1st()
        print("1st pass state size", getsizeof(state))
        crl1.encode2nd(buf.write, iter(state))
        print("DER 2pass encoded", time() - start)
        self.assertSequenceEqual(buf.getvalue(), raw)
        start = time()
        cer_raw = encode_cer(crl1)
        print("CER encoded", time() - start)
        start = time()
        crl2 = CertificateList().decod(cer_raw, ctx={"bered": True})
        print("CER decoded", time() - start)
        self.assertEqual(crl2, crl1)

    def test_mmaped(self):
        fd = open(CRL_PATH, "rb")
        start = time()
        CertificateList().decod(file_mmaped(fd))
        print("DER decoded", time() - start)

    def test_evgens(self):
        fd = open(CRL_PATH, "rb")
        raw = file_mmaped(fd)
        print("CRL opened")
        evgens_count = 0
        revoked_certs_count = 0
        start = time()
        for decode_path, _, _ in CertificateList().decode_evgen(raw):
            evgens_count += 1
            if (
                    len(decode_path) == 3 and
                    decode_path[:2] == ("tbsCertList", "revokedCertificates")
            ):
                revoked_certs_count += 1
        print("CRL parsed", time() - start)
        evgens_upto_count = 0
        start = time()
        for decode_path, _, _ in CertificateList().decode_evgen(raw, ctx={
                "evgen_mode_upto": (
                    (("tbsCertList", "revokedCertificates", any), True),
                ),
        }):
            evgens_upto_count += 1
        print("CRL upto parsed", time() - start)
        self.assertEqual(
            float(evgens_count - evgens_upto_count) / revoked_certs_count,
            3,
        )
