Examples
========

.. contents::

Schema definition
-----------------

Let's try to parse X.509 certificate. We have to define our structures
based on ASN.1 schema descriptions.

.. list-table::
   :header-rows: 1

   * - ASN.1 specification
     - pyderasn's code
   * - ::

            Certificate  ::=  SEQUENCE  {
                tbsCertificate       TBSCertificate,
                signatureAlgorithm   AlgorithmIdentifier,
                signatureValue       BIT STRING  }
     - ::

            class Certificate(Sequence):
                schema = (
                    ("tbsCertificate", TBSCertificate()),
                    ("signatureAlgorithm", AlgorithmIdentifier()),
                    ("signatureValue", BitString()),
                )
   * - ::

            AlgorithmIdentifier  ::=  SEQUENCE  {
                algorithm    OBJECT IDENTIFIER,
                parameters   ANY DEFINED BY algorithm OPTIONAL  }
     - ::

            class AlgorithmIdentifier(Sequence):
                schema = (
                    ("algorithm", ObjectIdentifier()),
                    ("parameters", Any(optional=True)),
                )
   * - ::

            TBSCertificate  ::=  SEQUENCE  {
                version         [0]  EXPLICIT Version DEFAULT v1,
                serialNumber         CertificateSerialNumber,
                signature            AlgorithmIdentifier,
                issuer               Name,
                validity             Validity,
                subject              Name,
                subjectPublicKeyInfo SubjectPublicKeyInfo,
                issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                extensions      [3]  EXPLICIT Extensions OPTIONAL  }
     - ::

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
   * - ::

            Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     - ::

            class Version(Integer):
                schema = (("v1", 0), ("v2", 1), ("v3", 2))
   * - ::

            CertificateSerialNumber  ::=  INTEGER
     - ::

            class CertificateSerialNumber(Integer):
                pass
   * - ::

            Validity ::= SEQUENCE {
                notBefore      Time,
                notAfter       Time }
            Time ::= CHOICE {
                utcTime        UTCTime,
                generalTime    GeneralizedTime }
     - ::

            class Validity(Sequence):
                schema = (
                    ("notBefore", Time()),
                    ("notAfter", Time()),
                )
            class Time(Choice):
                schema = (
                    ("utcTime", UTCTime()),
                    ("generalTime", GeneralizedTime()),
                )
   * - ::

            SubjectPublicKeyInfo  ::=  SEQUENCE  {
                algorithm            AlgorithmIdentifier,
                subjectPublicKey     BIT STRING  }
     - ::

            class SubjectPublicKeyInfo(Sequence):
                schema = (
                    ("algorithm", AlgorithmIdentifier()),
                    ("subjectPublicKey", BitString()),
                )
   * - ::

            UniqueIdentifier  ::=  BIT STRING
     - ::

            class UniqueIdentifier(BitString):
                pass
   * - ::

            Name ::= CHOICE { rdnSequence  RDNSequence }

            RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

            RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

            AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }

            AttributeType ::= OBJECT IDENTIFIER

            AttributeValue ::= ANY -- DEFINED BY AttributeType
     - ::

            class Name(Choice):
                schema = (("rdnSequence", RDNSequence()),)
            class RDNSequence(SequenceOf):
                schema = RelativeDistinguishedName()
            class RelativeDistinguishedName(SetOf):
                schema = AttributeTypeAndValue()
                bounds = (1, float("+inf"))
            class AttributeTypeAndValue(Sequence):
                schema = (
                    ("type", AttributeType()),
                    ("value", AttributeValue()),
                )
            class AttributeType(ObjectIdentifier):
                pass
            class AttributeValue(Any):
                pass
   * - ::

            Extensions ::=  SEQUENCE SIZE (1..MAX) OF Extension

            Extension  ::=  SEQUENCE  {
                extnID      OBJECT IDENTIFIER,
                critical    BOOLEAN DEFAULT FALSE,
                extnValue   OCTET STRING
                }
     - ::

            class Extensions(SequenceOf):
                schema = Extension()
                bounds = (1, float("+inf"))
            class Extension(Sequence):
                schema = (
                    ("extnID", ObjectIdentifier()),
                    ("critical", Boolean(default=False)),
                    ("extnValue", OctetString()),
                )

We are ready to decode PayPal's certificate from Go `encoding/asn1
<https://golang.org/pkg/encoding/asn1/>`__ test suite (assuming that
it's DER encoded representation is already in ``raw`` variable)::

    >>> crt = Certificate().decod(raw)
    >>> crt
    Certificate SEQUENCE[tbsCertificate: TBSCertificate SEQUENCE[
        version: [0] EXPLICIT Version INTEGER v3 OPTIONAL;
        serialNumber: CertificateSerialNumber INTEGER 61595;
        signature: AlgorithmIdentifier SEQUENCE[OBJECT IDENTIFIER 1.2.840.113549.1.1.5...

.. seealso:: :ref:`Better pretty printing <pprint_example>`

As command line utility
-----------------------

.. seealso:: :ref:`cmdline`

Descriptive errors
------------------

If you have bad DER/BER, then errors will show you where error occurred::

    $ python -m pyderasn --schema tests.test_crts:Certificate path/to/bad/file
    Traceback (most recent call last):
    [...]
    pyderasn.DecodeError: UTCTime (tbsCertificate:validity:notAfter:utcTime) (at 328) invalid UTCTime format

::

    $ python -m pyderasn path/to/bad/file
    [...]
    pyderasn.DecodeError: UTCTime (0:SequenceOf:4:SequenceOf:1:UTCTime) (at 328) invalid UTCTime format

You can see, so called, decode path inside the structures:
``tbsCertificate`` -> ``validity`` -> ``notAfter`` -> ``utcTime`` and
that object at byte 328 is invalid.

X.509 certificate creation
--------------------------

Let's create some simple self-signed X.509 certificate from the ground::

    tbs = TBSCertificate()
    tbs["serialNumber"] = CertificateSerialNumber(10143011886257155224)

    sign_algo_id = AlgorithmIdentifier((
        ("algorithm", ObjectIdentifier("1.2.840.113549.1.1.5")),
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
    issuer = Name(("rdnSequence", rdnSeq))
    tbs["issuer"] = issuer
    tbs["subject"] = issuer

    validity = Validity((
        ("notBefore", Time(
            ("utcTime", UTCTime(datetime(2009, 10, 8, 0, 25, 53))),
        )),
        ("notAfter", Time(
            ("utcTime", UTCTime(datetime(2010, 10, 8, 0, 25, 53))),
        )),
    ))
    tbs["validity"] = validity

    spki = SubjectPublicKeyInfo()
    spki_algo_id = copy(sign_algo_id)
    spki_algo_id["algorithm"] = ObjectIdentifier("1.2.840.113549.1.1.1")
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
    crt.encode()

And we will get the same certificate used in Go's library tests.

DEFINED BY fields
-----------------

Here is only very simple example how you can define Any/OctetString
fields automatic decoding::

    class AttributeTypeAndValue(Sequence):
        schema = (
            ((("type",), AttributeType(defines=((("value",), {
                id_at_countryName: PrintableString(),
                id_at_stateOrProvinceName: PrintableString(),
                id_at_localityName: PrintableString(),
                id_at_organizationName: PrintableString(),
                id_at_commonName: PrintableString(),
            }),)))),
            ("value", AttributeValue()),
        )

And when you will try to decode X.509 certificate with it, your pretty
printer will show::

       34   [0,0, 149]  . . issuer: Name CHOICE rdnSequence
       34   [1,2, 146]  . . . rdnSequence: RDNSequence SEQUENCE OF
       37   [1,1,  11]  . . . . 0: RelativeDistinguishedName SET OF
       39   [1,1,   9]  . . . . . 0: AttributeTypeAndValue SEQUENCE
       41   [1,1,   3]  . . . . . . type: AttributeType OBJECT IDENTIFIER id-at-countryName (2.5.4.6)
       46   [0,0,   4]  . . . . . . value: [UNIV 19] AttributeValue ANY
                        . . . . . . . 13:02:58:58
       46   [1,1,   2]  . . . . . . . DEFINED BY (2.5.4.6): PrintableString PrintableString XX
       50   [1,1,  19]  . . . . 1: RelativeDistinguishedName SET OF
       52   [1,1,  17]  . . . . . 0: AttributeTypeAndValue SEQUENCE
       54   [1,1,   3]  . . . . . . type: AttributeType OBJECT IDENTIFIER id-at-stateOrProvinceName (2.5.4.8)
       59   [0,0,  12]  . . . . . . value: [UNIV 19] AttributeValue ANY
                        . . . . . . . 13:0A:53:6F:6D:65:2D:53:74:61:74:65
       59   [1,1,  10]  . . . . . . . DEFINED BY (2.5.4.8): PrintableString PrintableString Some-State
       71   [1,1,  13]  . . . . 2: RelativeDistinguishedName SET OF
       73   [1,1,  11]  . . . . . 0: AttributeTypeAndValue SEQUENCE
       75   [1,1,   3]  . . . . . . type: AttributeType OBJECT IDENTIFIER id-at-localityName (2.5.4.7)
       80   [0,0,   6]  . . . . . . value: [UNIV 19] AttributeValue ANY
                        . . . . . . . 13:04:43:69:74:79
       80   [1,1,   4]  . . . . . . . DEFINED BY (2.5.4.7): PrintableString PrintableString City
       86   [1,1,  33]  . . . . 3: RelativeDistinguishedName SET OF
       88   [1,1,  31]  . . . . . 0: AttributeTypeAndValue SEQUENCE
       90   [1,1,   3]  . . . . . . type: AttributeType OBJECT IDENTIFIER id-at-organizationName (2.5.4.10)
       95   [0,0,  26]  . . . . . . value: [UNIV 19] AttributeValue ANY
                        . . . . . . . 13:18:49:6E:74:65:72:6E:65:74:20:57:69:64:67:69
                        . . . . . . . 74:73:20:50:74:79:20:4C:74:64
       95   [1,1,  24]  . . . . . . . DEFINED BY (2.5.4.10): PrintableString PrintableString Internet Widgits Pty Ltd

.. seealso:: :ref:`definedby`

Streaming and dealing with huge structures
------------------------------------------
.. seealso:: :ref:`streaming`
