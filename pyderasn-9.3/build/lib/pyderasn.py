#!/usr/bin/env python
# coding: utf-8
# cython: language_level=3
# pylint: disable=line-too-long,superfluous-parens,protected-access,too-many-lines
# pylint: disable=too-many-return-statements,too-many-branches,too-many-statements
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
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Python ASN.1 DER/CER/BER codec with abstract structures

This library allows you to marshal various structures in ASN.1 DER/CER
format, unmarshal BER/CER/DER ones.

    >>> i = Integer(123)
    >>> raw = i.encode()
    >>> Integer().decod(raw) == i
    True

There are primitive types, holding single values
(:py:class:`pyderasn.BitString`,
:py:class:`pyderasn.Boolean`,
:py:class:`pyderasn.Enumerated`,
:py:class:`pyderasn.GeneralizedTime`,
:py:class:`pyderasn.Integer`,
:py:class:`pyderasn.Null`,
:py:class:`pyderasn.ObjectIdentifier`,
:py:class:`pyderasn.OctetString`,
:py:class:`pyderasn.UTCTime`,
:py:class:`various strings <pyderasn.CommonString>`
(:py:class:`pyderasn.BMPString`,
:py:class:`pyderasn.GeneralString`,
:py:class:`pyderasn.GraphicString`,
:py:class:`pyderasn.IA5String`,
:py:class:`pyderasn.ISO646String`,
:py:class:`pyderasn.NumericString`,
:py:class:`pyderasn.PrintableString`,
:py:class:`pyderasn.T61String`,
:py:class:`pyderasn.TeletexString`,
:py:class:`pyderasn.UniversalString`,
:py:class:`pyderasn.UTF8String`,
:py:class:`pyderasn.VideotexString`,
:py:class:`pyderasn.VisibleString`)),
constructed types, holding multiple primitive types
(:py:class:`pyderasn.Sequence`,
:py:class:`pyderasn.SequenceOf`,
:py:class:`pyderasn.Set`,
:py:class:`pyderasn.SetOf`),
and special types like
:py:class:`pyderasn.Any` and
:py:class:`pyderasn.Choice`.

Common for most types
---------------------

Tags
____

Most types in ASN.1 has specific tag for them. ``Obj.tag_default`` is
the default tag used during coding process. You can override it with
either ``IMPLICIT`` (using either ``impl`` keyword argument or ``impl``
class attribute), or ``EXPLICIT`` one (using either ``expl`` keyword
argument or ``expl`` class attribute). Both arguments take raw binary
string, containing that tag. You can **not** set implicit and explicit
tags simultaneously.

There are :py:func:`pyderasn.tag_ctxp` and :py:func:`pyderasn.tag_ctxc`
functions, allowing you to easily create ``CONTEXT``
``PRIMITIVE``/``CONSTRUCTED`` tags, by specifying only the required tag
number.

.. note::

   EXPLICIT tags always have **constructed** tag. PyDERASN does not
   explicitly check correctness of schema input here.

.. note::

   Implicit tags have **primitive** (``tag_ctxp``) encoding for
   primitive values.

::

    >>> Integer(impl=tag_ctxp(1))
    [1] INTEGER
    >>> Integer(expl=tag_ctxc(2))
    [2] EXPLICIT INTEGER

Implicit tag is not explicitly shown.

Two objects of the same type, but with different implicit/explicit tags
are **not** equal.

You can get object's effective tag (either default or implicited) through
``tag`` property. You can decode it using :py:func:`pyderasn.tag_decode`
function::

    >>> tag_decode(tag_ctxc(123))
    (128, 32, 123)
    >>> klass, form, num = tag_decode(tag_ctxc(123))
    >>> klass == TagClassContext
    True
    >>> form == TagFormConstructed
    True

To determine if object has explicit tag, use ``expled`` boolean property
and ``expl_tag`` property, returning explicit tag's value.

Default/optional
________________

Many objects in sequences could be ``OPTIONAL`` and could have
``DEFAULT`` value. You can specify that object's property using
corresponding keyword arguments.

    >>> Integer(optional=True, default=123)
    INTEGER 123 OPTIONAL DEFAULT

Those specifications do not play any role in primitive value encoding,
but are taken into account when dealing with sequences holding them. For
example ``TBSCertificate`` sequence holds defaulted, explicitly tagged
``version`` field::

    class Version(Integer):
        schema = (
            ("v1", 0),
            ("v2", 1),
            ("v3", 2),
        )
    class TBSCertificate(Sequence):
        schema = (
            ("version", Version(expl=tag_ctxc(0), default="v1")),
        [...]

When default argument is used and value is not specified, then it equals
to default one.

.. _bounds:

Size constraints
________________

Some objects give ability to set value size constraints. This is either
possible integer value, or allowed length of various strings and
sequences. Constraints are set in the following way::

    class X(...):
        bounds = (MIN, MAX)

And values satisfaction is checked as: ``MIN <= X <= MAX``.

For simplicity you can also set bounds the following way::

    bounded_x = X(bounds=(MIN, MAX))

If bounds are not satisfied, then :py:exc:`pyderasn.BoundsError` is
raised.

Common methods
______________

All objects have ``ready`` boolean property, that tells if object is
ready to be encoded. If that kind of action is performed on unready
object, then :py:exc:`pyderasn.ObjNotReady` exception will be raised.

All objects are friendly to ``copy.copy()`` and copied objects can be
safely mutated.

Also all objects can be safely ``pickle``-d, but pay attention that
pickling among different PyDERASN versions is prohibited.

.. _decoding:

Decoding
--------

Decoding is performed using :py:meth:`pyderasn.Obj.decode` method.
``offset`` optional argument could be used to set initial object's
offset in the binary data, for convenience. It returns decoded object
and remaining unmarshalled data (tail). Internally all work is done on
``memoryview(data)``, and you can leave returning tail as a memoryview,
by specifying ``leavemm=True`` argument.

Also note convenient :py:meth:`pyderasn.Obj.decod` method, that
immediately checks and raises if there is non-empty tail.

When object is decoded, ``decoded`` property is true and you can safely
use following properties:

* ``offset`` -- position including initial offset where object's tag starts
* ``tlen`` -- length of object's tag
* ``llen`` -- length of object's length value
* ``vlen`` -- length of object's value
* ``tlvlen`` -- length of the whole object

Pay attention that those values do **not** include anything related to
explicit tag. If you want to know information about it, then use:

* ``expled`` -- to know if explicit tag is set
* ``expl_offset`` (it is lesser than ``offset``)
* ``expl_tlen``,
* ``expl_llen``
* ``expl_vlen`` (that actually equals to ordinary ``tlvlen``)
* ``fulloffset`` -- it equals to ``expl_offset`` if explicit tag is set,
  ``offset`` otherwise
* ``fulllen`` -- it equals to ``expl_len`` if explicit tag is set,
  ``tlvlen`` otherwise

When error occurs, :py:exc:`pyderasn.DecodeError` is raised.

.. _ctx:

Context
_______

You can specify so called context keyword argument during
:py:meth:`pyderasn.Obj.decode` invocation. It is dictionary containing
various options governing decoding process.

Currently available context options:

* :ref:`allow_default_values <allow_default_values_ctx>`
* :ref:`allow_expl_oob <allow_expl_oob_ctx>`
* :ref:`allow_unordered_set <allow_unordered_set_ctx>`
* :ref:`bered <bered_ctx>`
* :ref:`defines_by_path <defines_by_path_ctx>`
* :ref:`evgen_mode_upto <evgen_mode_upto_ctx>`
* :ref:`keep_memoryview <keep_memoryview_ctx>`

.. _pprinting:

Pretty printing
---------------

All objects have ``pps()`` method, that is a generator of
:py:class:`pyderasn.PP` namedtuple, holding various raw information
about the object. If ``pps`` is called on sequences, then all underlying
``PP`` will be yielded.

You can use :py:func:`pyderasn.pp_console_row` function, converting
those ``PP`` to human readable string. Actually exactly it is used for
all object ``repr``. But it is easy to write custom formatters.

    >>> from pyderasn import pprint
    >>> encoded = Integer(-12345).encode()
    >>> obj, tail = Integer().decode(encoded)
    >>> print(pprint(obj))
        0   [1,1,   2] INTEGER -12345

.. _pprint_example:

Example certificate::

    >>> print(pprint(crt))
        0   [1,3,1604] Certificate SEQUENCE
        4   [1,3,1453]  . tbsCertificate: TBSCertificate SEQUENCE
       10-2 [1,1,   1]  . . version: [0] EXPLICIT Version INTEGER v3 OPTIONAL
       13   [1,1,   3]  . . serialNumber: CertificateSerialNumber INTEGER 61595
       18   [1,1,  13]  . . signature: AlgorithmIdentifier SEQUENCE
       20   [1,1,   9]  . . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
       31   [0,0,   2]  . . . parameters: [UNIV 5] ANY OPTIONAL
                        . . . . 05:00
       33   [0,0, 278]  . . issuer: Name CHOICE rdnSequence
       33   [1,3, 274]  . . . rdnSequence: RDNSequence SEQUENCE OF
       37   [1,1,  11]  . . . . 0: RelativeDistinguishedName SET OF
       39   [1,1,   9]  . . . . . 0: AttributeTypeAndValue SEQUENCE
       41   [1,1,   3]  . . . . . . type: AttributeType OBJECT IDENTIFIER 2.5.4.6
       46   [0,0,   4]  . . . . . . value: [UNIV 19] AttributeValue ANY
                        . . . . . . . 13:02:45:53
    [...]
     1461   [1,1,  13]  . signatureAlgorithm: AlgorithmIdentifier SEQUENCE
     1463   [1,1,   9]  . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
     1474   [0,0,   2]  . . parameters: [UNIV 5] ANY OPTIONAL
                        . . . 05:00
     1476   [1,2, 129]  . signatureValue: BIT STRING 1024 bits
                        . . 68:EE:79:97:97:DD:3B:EF:16:6A:06:F2:14:9A:6E:CD
                        . . 9E:12:F7:AA:83:10:BD:D1:7C:98:FA:C7:AE:D4:0E:2C
     [...]

    Trailing data: 0a

Let's parse that output, human::

       10-2 [1,1,   1]    . . version: [0] EXPLICIT Version INTEGER v3 OPTIONAL
       ^  ^  ^ ^    ^     ^   ^        ^            ^       ^       ^  ^
       0  1  2 3    4     5   6        7            8       9       10 11

::

       20   [1,1,   9]    . . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
       ^     ^ ^    ^     ^     ^          ^                 ^
       0     2 3    4     5     6          9                 10

::

       33   [0,0, 278]    . . issuer: Name CHOICE rdnSequence
       ^     ^ ^    ^     ^   ^       ^    ^      ^
       0     2 3    4     5   6       8    9      10

::

       52-2∞ B [1,1,1054]∞  . . . . eContent: [0] EXPLICIT BER OCTET STRING 1046 bytes
             ^           ^                                 ^   ^            ^
            12          13                                14   9            10

:0:
 Offset of the object, where its DER/BER encoding begins.
 Pay attention that it does **not** include explicit tag.
:1:
 If explicit tag exists, then this is its length (tag + encoded length).
:2:
 Length of object's tag. For example CHOICE does not have its own tag,
 so it is zero.
:3:
 Length of encoded length.
:4:
 Length of encoded value.
:5:
 Visual indentation to show the depth of object in the hierarchy.
:6:
 Object's name inside SEQUENCE/CHOICE.
:7:
 If either IMPLICIT or EXPLICIT tag is set, then it will be shown
 here. "IMPLICIT" is omitted.
:8:
 Object's class name, if set. Omitted if it is just an ordinary simple
 value (like with ``algorithm`` in example above).
:9:
 Object's ASN.1 type.
:10:
 Object's value, if set. Can consist of multiple words (like OCTET/BIT
 STRINGs above). We see ``v3`` value in Version, because it is named.
 ``rdnSequence`` is the choice of CHOICE type.
:11:
 Possible other flags like OPTIONAL and DEFAULT, if value equals to the
 default one, specified in the schema.
:12:
 Shows does object contains any kind of BER encoded data (possibly
 Sequence holding BER-encoded underlying value).
:13:
 Only applicable to BER encoded data. Indefinite length encoding mark.
:14:
 Only applicable to BER encoded data. If object has BER-specific
 encoding, then ``BER`` will be shown. It does not depend on indefinite
 length encoding. ``EOC``, ``BOOLEAN``, ``BIT STRING``, ``OCTET STRING``
 (and its derivatives), ``SET``, ``SET OF``, ``UTCTime``, ``GeneralizedTime``
 could be BERed.

Also it could be helpful to add quick ASN.1 pprinting command in your
pdb's configuration file::

    alias pp1 import pyderasn ;; print(pyderasn.pprint(%1, oid_maps=(locals().get("OID_STR_TO_NAME", {}),)))

.. _definedby:

DEFINED BY
----------

ASN.1 structures often have ANY and OCTET STRING fields, that are
DEFINED BY some previously met ObjectIdentifier. This library provides
ability to specify mapping between some OID and field that must be
decoded with specific specification.

.. _defines:

defines kwarg
_____________

:py:class:`pyderasn.ObjectIdentifier` field inside
:py:class:`pyderasn.Sequence` can hold mapping between OIDs and
necessary for decoding structures. For example, CMS (:rfc:`5652`)
container::

    class ContentInfo(Sequence):
        schema = (
            ("contentType", ContentType(defines=((("content",), {
                id_digestedData: DigestedData(),
                id_signedData: SignedData(),
            }),))),
            ("content", Any(expl=tag_ctxc(0))),
        )

``contentType`` field tells that it defines that ``content`` must be
decoded with ``SignedData`` specification, if ``contentType`` equals to
``id-signedData``. The same applies to ``DigestedData``. If
``contentType`` contains unknown OID, then no automatic decoding is
done.

You can specify multiple fields, that will be autodecoded -- that is why
``defines`` kwarg is a sequence. You can specify defined field
relatively or absolutely to current decode path. For example ``defines``
for AlgorithmIdentifier of X.509's
``tbsCertificate:subjectPublicKeyInfo:algorithm:algorithm``::

        (
            (("parameters",), {
                id_ecPublicKey: ECParameters(),
                id_GostR3410_2001: GostR34102001PublicKeyParameters(),
            }),
            (("..", "subjectPublicKey"), {
                id_rsaEncryption: RSAPublicKey(),
                id_GostR3410_2001: OctetString(),
            }),
        ),

tells that if certificate's SPKI algorithm is GOST R 34.10-2001, then
autodecode its parameters inside SPKI's algorithm and its public key
itself.

Following types can be automatically decoded (DEFINED BY):

* :py:class:`pyderasn.Any`
* :py:class:`pyderasn.BitString` (that is multiple of 8 bits)
* :py:class:`pyderasn.OctetString`
* :py:class:`pyderasn.SequenceOf`/:py:class:`pyderasn.SetOf`
  ``Any``/``BitString``/``OctetString``-s

When any of those fields is automatically decoded, then ``.defined``
attribute contains ``(OID, value)`` tuple. ``OID`` tells by which OID it
was defined, ``value`` contains corresponding decoded value. For example
above, ``content_info["content"].defined == (id_signedData, signed_data)``.

.. _defines_by_path_ctx:

defines_by_path context option
______________________________

Sometimes you either can not or do not want to explicitly set *defines*
in the schema. You can dynamically apply those definitions when calling
:py:meth:`pyderasn.Obj.decode` method.

Specify ``defines_by_path`` key in the :ref:`decode context <ctx>`. Its
value must be sequence of following tuples::

    (decode_path, defines)

where ``decode_path`` is a tuple holding so-called decode path to the
exact :py:class:`pyderasn.ObjectIdentifier` field you want to apply
``defines``, holding exactly the same value as accepted in its
:ref:`keyword argument <defines>`.

For example, again for CMS, you want to automatically decode
``SignedData`` and CMC's (:rfc:`5272`) ``PKIData`` and ``PKIResponse``
structures it may hold. Also, automatically decode ``controlSequence``
of ``PKIResponse``::

    content_info = ContentInfo().decod(data, ctx={"defines_by_path": (
        (
            ("contentType",),
            ((("content",), {id_signedData: SignedData()}),),
        ),
        (
            (
                "content",
                DecodePathDefBy(id_signedData),
                "encapContentInfo",
                "eContentType",
            ),
            ((("eContent",), {
                id_cct_PKIData: PKIData(),
                id_cct_PKIResponse: PKIResponse(),
            })),
        ),
        (
            (
                "content",
                DecodePathDefBy(id_signedData),
                "encapContentInfo",
                "eContent",
                DecodePathDefBy(id_cct_PKIResponse),
                "controlSequence",
                any,
                "attrType",
            ),
            ((("attrValues",), {
                id_cmc_recipientNonce: RecipientNonce(),
                id_cmc_senderNonce: SenderNonce(),
                id_cmc_statusInfoV2: CMCStatusInfoV2(),
                id_cmc_transactionId: TransactionId(),
            })),
        ),
    )})

Pay attention for :py:class:`pyderasn.DecodePathDefBy` and ``any``.
First function is useful for path construction when some automatic
decoding is already done. ``any`` means literally any value it meet --
useful for SEQUENCE/SET OF-s.

.. _bered_ctx:

BER encoding
------------

By default PyDERASN accepts only DER encoded data. By default it encodes
to DER. But you can optionally enable BER decoding with setting
``bered`` :ref:`context <ctx>` argument to True. Indefinite lengths and
constructed primitive types should be parsed successfully.

* If object is encoded in BER form (not the DER one), then ``ber_encoded``
  attribute is set to True. Only ``BOOLEAN``, ``BIT STRING``, ``OCTET
  STRING``, ``OBJECT IDENTIFIER``, ``SEQUENCE``, ``SET``, ``SET OF``,
  ``UTCTime``, ``GeneralizedTime`` can contain it.
* If object has an indefinite length encoding, then its ``lenindef``
  attribute is set to True. Only ``BIT STRING``, ``OCTET STRING``,
  ``SEQUENCE``, ``SET``, ``SEQUENCE OF``, ``SET OF``, ``ANY`` can
  contain it.
* If object has an indefinite length encoded explicit tag, then
  ``expl_lenindef`` is set to True.
* If object has either any of BER-related encoding (explicit tag
  indefinite length, object's indefinite length, BER-encoding) or any
  underlying component has that kind of encoding, then ``bered``
  attribute is set to True. For example SignedData CMS can have
  ``ContentInfo:content:signerInfos:*`` ``bered`` value set to True, but
  ``ContentInfo:content:signerInfos:*:signedAttrs`` won't.

EOC (end-of-contents) token's length is taken in advance in object's
value length.

.. _allow_expl_oob_ctx:

Allow explicit tag out-of-bound
-------------------------------

Invalid BER encoding could contain ``EXPLICIT`` tag containing more than
one value, more than one object. If you set ``allow_expl_oob`` context
option to True, then no error will be raised and that invalid encoding
will be silently further processed. But pay attention that offsets and
lengths will be invalid in that case.

.. warning::

   This option should be used only for skipping some decode errors, just
   to see the decoded structure somehow.

.. _streaming:

Streaming and dealing with huge structures
------------------------------------------

.. _evgen_mode:

evgen mode
__________

ASN.1 structures can be huge, they can hold millions of objects inside
(for example Certificate Revocation Lists (CRL), holding revocation
state for every previously issued X.509 certificate). CACert.org's 8 MiB
CRL file takes more than half a gigabyte of memory to hold the decoded
structure.

If you just simply want to check the signature over the ``tbsCertList``,
you can create specialized schema with that field represented as
OctetString for example::

    class TBSCertListFast(Sequence):
        schema = (
            [...]
            ("revokedCertificates", OctetString(
                impl=SequenceOf.tag_default,
                optional=True,
            )),
            [...]
        )

This allows you to quickly decode a few fields and check the signature
over the ``tbsCertList`` bytes.

But how can you get all certificate's serial number from it, after you
trust that CRL after signature validation? You can use so called
``evgen`` (event generation) mode, to catch the events/facts of some
successful object decoding. Let's use command line capabilities::

    $ python -m pyderasn --schema tests.test_crl:CertificateList --evgen revoke.crl
         10     [1,1,   1]   . . version: Version INTEGER v2 (01) OPTIONAL
         15     [1,1,   9]   . . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.13
         26     [0,0,   2]   . . . parameters: [UNIV 5] ANY OPTIONAL
         13     [1,1,  13]   . . signature: AlgorithmIdentifier SEQUENCE
         34     [1,1,   3]   . . . . . . type: AttributeType OBJECT IDENTIFIER 2.5.4.10
         39     [0,0,   9]   . . . . . . value: [UNIV 19] AttributeValue ANY
         32     [1,1,  14]   . . . . . 0: AttributeTypeAndValue SEQUENCE
         30     [1,1,  16]   . . . . 0: RelativeDistinguishedName SET OF
    [...]
        188     [1,1,   1]   . . . . userCertificate: CertificateSerialNumber INTEGER 17 (11)
        191     [1,1,  13]   . . . . . utcTime: UTCTime UTCTime 2003-04-01T14:25:08
        191     [0,0,  15]   . . . . revocationDate: Time CHOICE utcTime
        191     [1,1,  13]   . . . . . utcTime: UTCTime UTCTime 2003-04-01T14:25:08
        186     [1,1,  18]   . . . 0: RevokedCertificate SEQUENCE
        208     [1,1,   1]   . . . . userCertificate: CertificateSerialNumber INTEGER 20 (14)
        211     [1,1,  13]   . . . . . utcTime: UTCTime UTCTime 2002-10-01T02:18:01
        211     [0,0,  15]   . . . . revocationDate: Time CHOICE utcTime
        211     [1,1,  13]   . . . . . utcTime: UTCTime UTCTime 2002-10-01T02:18:01
        206     [1,1,  18]   . . . 1: RevokedCertificate SEQUENCE
    [...]
    9144992     [0,0,  15]   . . . . revocationDate: Time CHOICE utcTime
    9144992     [1,1,  13]   . . . . . utcTime: UTCTime UTCTime 2020-02-08T07:25:06
    9144985     [1,1,  20]   . . . 415755: RevokedCertificate SEQUENCE
      181     [1,4,9144821]   . . revokedCertificates: RevokedCertificates SEQUENCE OF OPTIONAL
        5     [1,4,9144997]   . tbsCertList: TBSCertList SEQUENCE
    9145009     [1,1,   9]   . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.13
    9145020     [0,0,   2]   . . parameters: [UNIV 5] ANY OPTIONAL
    9145007     [1,1,  13]   . signatureAlgorithm: AlgorithmIdentifier SEQUENCE
    9145022     [1,3, 513]   . signatureValue: BIT STRING 4096 bits
        0     [1,4,9145534]  CertificateList SEQUENCE

Here we see how decoder works: it decodes SEQUENCE's tag, length, then
decodes underlying values. It can not tell if SEQUENCE is decoded, so
the event of the upper level SEQUENCE is the last one we see.
``version`` field is just a single INTEGER -- it is decoded and event is
fired immediately. Then we see that ``algorithm`` and ``parameters``
fields are decoded and only after them the ``signature`` SEQUENCE is
fired as a successfully decoded. There are 4 events for each revoked
certificate entry in that CRL: ``userCertificate`` serial number,
``utcTime`` of ``revocationDate`` CHOICE, ``RevokedCertificate`` itself
as a one of entity in ``revokedCertificates`` SEQUENCE OF.

We can do that in our ordinary Python code and understand where we are
by looking at deterministically generated decode paths (do not forget
about useful ``--print-decode-path`` CLI option). We must use
:py:meth:`pyderasn.Obj.decode_evgen` method, instead of ordinary
:py:meth:`pyderasn.Obj.decode`. It is generator yielding ``(decode_path,
obj, tail)`` tuples::

    for decode_path, obj, _ in CertificateList().decode_evgen(crl_raw):
        if (
            len(decode_path) == 4 and
            decode_path[:2] == ("tbsCertList", "revokedCertificates"),
            decode_path[3] == "userCertificate"
        ):
            print("serial number:", int(obj))

Virtually it does not take any memory except at least needed for single
object storage. You can easily use that mode to determine required
object ``.offset`` and ``.*len`` to be able to decode it separately, or
maybe verify signature upon it just by taking bytes by ``.offset`` and
``.tlvlen``.

.. _evgen_mode_upto_ctx:

evgen_mode_upto
_______________

There is full ability to get any kind of data from the CRL in the
example above. However it is not too convenient to get the whole
``RevokedCertificate`` structure, that is pretty lightweight and one may
do not want to disassemble it. You can use ``evgen_mode_upto``
:ref:`ctx <ctx>` option that semantically equals to
:ref:`defines_by_path <defines_by_path_ctx>` -- list of decode paths
mapped to any non-None value. If specified decode path is met, then any
subsequent objects won't be decoded in evgen mode. That allows us to
parse the CRL above with fully assembled ``RevokedCertificate``::

    for decode_path, obj, _ in CertificateList().decode_evgen(
        crl_raw,
        ctx={"evgen_mode_upto": (
            (("tbsCertList", "revokedCertificates", any), True),
        )},
    ):
        if (
            len(decode_path) == 3 and
            decode_path[:2] == ("tbsCertList", "revokedCertificates"),
        ):
            print("serial number:", int(obj["userCertificate"]))

.. note::

   SEQUENCE/SET values with DEFAULT specified are automatically decoded
   without evgen mode.

.. _mmap:

mmap-ed file
____________

POSIX compliant systems have ``mmap`` syscall, giving ability to work
the memory mapped file. You can deal with the file like it was an
ordinary binary string, allowing you not to load it to the memory first.
Also you can use them as an input for OCTET STRING, taking no Python
memory for their storage.

There is convenient :py:func:`pyderasn.file_mmaped` function that
creates read-only memoryview on the file contents::

    with open("huge", "rb") as fd:
        raw = file_mmaped(fd)
        obj = Something.decode(raw)

.. warning::

   mmap maps the **whole** file. So it plays no role if you seek-ed it
   before. Take the slice of the resulting memoryview with required
   offset instead.

.. note::

   If you use ZFS as underlying storage, then pay attention that
   currently most platforms does not deal good with ZFS ARC and ordinary
   page cache used for mmaps. It can take twice the necessary size in
   the memory: both in page cache and ZFS ARC.

.. _keep_memoryview_ctx:

That read-only memoryview could be safe to be used as a value inside
decoded :py:class:`pyderasn.OctetString` and :py:class:`pyderasn.Any`
objects. You can enable that by setting `"keep_memoryview": True` in
:ref:`decode context <ctx>`. No OCTET STRING and ANY values will be
copied to memory. Of course that works only in DER encoding, where the
value is continuously encoded.

CER encoding
____________

We can parse any kind of data now, but how can we produce files
streamingly, without storing their encoded representation in memory?
SEQUENCE by default encodes in memory all its values, joins them in huge
binary string, just to know the exact size of SEQUENCE's value for
encoding it in TLV. DER requires you to know all exact sizes of the
objects.

You can use CER encoding mode, that slightly differs from the DER, but
does not require exact sizes knowledge, allowing streaming encoding
directly to some writer/buffer. Just use
:py:meth:`pyderasn.Obj.encode_cer` method, providing the writer where
encoded data will flow::

    with open("result", "wb") as fd:
        obj.encode_cer(fd.write)

::

    buf = io.BytesIO()
    obj.encode_cer(buf.write)

If you do not want to create in-memory buffer every time, then you can
use :py:func:`pyderasn.encode_cer` function::

    data = encode_cer(obj)

Remember that CER is **not valid** DER in most cases, so you **have to**
use :ref:`bered <bered_ctx>` :ref:`ctx <ctx>` option during its
decoding. Also currently there is **no** validation that provided CER is
valid one -- you are sure that it has only valid BER encoding.

.. warning::

   SET OF values can not be streamingly encoded, because they are
   required to be sorted byte-by-byte. Big SET OF values still will take
   much memory. Use neither SET nor SET OF values, as modern ASN.1
   also recommends too.

Do not forget about using :ref:`mmap-ed <mmap>` memoryviews for your
OCTET STRINGs! They will be streamingly copied from underlying file to
the buffer using 1 KB chunks.

Some structures require that some of the elements have to be forcefully
DER encoded. For example ``SignedData`` CMS requires you to encode
``SignedAttributes`` and X.509 certificates in DER form, allowing you to
encode everything else in BER. You can tell any of the structures to be
forcefully encoded in DER during CER encoding, by specifying
``der_forced=True`` attribute::

    class Certificate(Sequence):
        schema = (...)
        der_forced = True

    class SignedAttributes(SetOf):
        schema = Attribute()
        bounds = (1, float("+inf"))
        der_forced = True

.. _agg_octet_string:

agg_octet_string
________________

In most cases, huge quantity of binary data is stored as OCTET STRING.
CER encoding splits it on 1 KB chunks. BER allows splitting on various
levels of chunks inclusion::

    SOME STRING[CONSTRUCTED]
        OCTET STRING[CONSTRUCTED]
            OCTET STRING[PRIMITIVE]
                DATA CHUNK
            OCTET STRING[PRIMITIVE]
                DATA CHUNK
            OCTET STRING[PRIMITIVE]
                DATA CHUNK
        OCTET STRING[PRIMITIVE]
            DATA CHUNK
        OCTET STRING[CONSTRUCTED]
            OCTET STRING[PRIMITIVE]
                DATA CHUNK
            OCTET STRING[PRIMITIVE]
                DATA CHUNK
        OCTET STRING[CONSTRUCTED]
            OCTET STRING[CONSTRUCTED]
                OCTET STRING[PRIMITIVE]
                    DATA CHUNK

You can not just take the offset and some ``.vlen`` of the STRING and
treat it as the payload. If you decode it without
:ref:`evgen mode <evgen_mode>`, then it will be automatically aggregated
and ``bytes()`` will give the whole payload contents.

You are forced to use :ref:`evgen mode <evgen_mode>` for decoding for
small memory footprint. There is convenient
:py:func:`pyderasn.agg_octet_string` helper for reconstructing the
payload. Let's assume you have got BER/CER encoded ``ContentInfo`` with
huge ``SignedData`` and ``EncapsulatedContentInfo``. Let's calculate the
SHA512 digest of its ``eContent``::

    fd = open("data.p7m", "rb")
    raw = file_mmaped(fd)
    ctx = {"bered": True}
    for decode_path, obj, _ in ContentInfo().decode_evgen(raw, ctx=ctx):
        if decode_path == ("content",):
            content = obj
            break
    else:
        raise ValueError("no content found")
    hasher_state = sha512()
    def hasher(data):
        hasher_state.update(data)
        return len(data)
    evgens = SignedData().decode_evgen(
        raw[content.offset:],
        offset=content.offset,
        ctx=ctx,
    )
    agg_octet_string(evgens, ("encapContentInfo", "eContent"), raw, hasher)
    fd.close()
    digest = hasher_state.digest()

Simply replace ``hasher`` with some writeable file's ``fd.write`` to
copy the payload (without BER/CER encoding interleaved overhead) in it.
Virtually it won't take memory more than for keeping small structures
and 1 KB binary chunks.

.. _seqof-iterators:

SEQUENCE OF iterators
_____________________

You can use iterators as a value in :py:class:`pyderasn.SequenceOf`
classes. The only difference with providing the full list of objects, is
that type and bounds checking is done during encoding process. Also
sequence's value will be emptied after encoding, forcing you to set its
value again.

This is very useful when you have to create some huge objects, like
CRLs, with thousands and millions of entities inside. You can write the
generator taking necessary data from the database and giving the
``RevokedCertificate`` objects. Only binary representation of that
objects will take memory during DER encoding.

2-pass DER encoding
-------------------

There is ability to do 2-pass encoding to DER, writing results directly
to specified writer (buffer, file, whatever). It could be 1.5+ times
slower than ordinary encoding, but it takes little memory for 1st pass
state storing. For example, 1st pass state for CACert.org's CRL with
~416K of certificate entries takes nearly 3.5 MB of memory.
``SignedData`` with several gigabyte ``EncapsulatedContentInfo`` takes
nearly 0.5 KB of memory.

If you use :ref:`mmap-ed <mmap>` memoryviews, :ref:`SEQUENCE OF
iterators <seqof-iterators>` and write directly to opened file, then
there is very small memory footprint.

1st pass traverses through all the objects of the structure and returns
the size of DER encoded structure, together with 1st pass state object.
That state contains precalculated lengths for various objects inside the
structure.

::

    fulllen, state = obj.encode1st()

2nd pass takes the writer and 1st pass state. It traverses through all
the objects again, but writes their encoded representation to the writer.

::

    with open("result", "wb") as fd:
        obj.encode2nd(fd.write, iter(state))

.. warning::

   You **MUST NOT** use 1st pass state if anything is changed in the
   objects. It is intended to be used immediately after 1st pass is
   done!

If you use :ref:`SEQUENCE OF iterators <seqof-iterators>`, then you
have to reinitialize the values after the 1st pass. And you **have to**
be sure that the iterator gives exactly the same values as previously.
Yes, you have to run your iterator twice -- because this is two pass
encoding mode.

If you want to encode to the memory, then you can use convenient
:py:func:`pyderasn.encode2pass` helper.

.. _browser:

ASN.1 browser
-------------
.. autofunction:: pyderasn.browse

Base Obj
--------
.. autoclass:: pyderasn.Obj
   :members:

Primitive types
---------------

Boolean
_______
.. autoclass:: pyderasn.Boolean
   :members: __init__

Integer
_______
.. autoclass:: pyderasn.Integer
   :members: __init__, named, tohex

BitString
_________
.. autoclass:: pyderasn.BitString
   :members: __init__, bit_len, named

OctetString
___________
.. autoclass:: pyderasn.OctetString
   :members: __init__

Null
____
.. autoclass:: pyderasn.Null
   :members: __init__

ObjectIdentifier
________________
.. autoclass:: pyderasn.ObjectIdentifier
   :members: __init__

Enumerated
__________
.. autoclass:: pyderasn.Enumerated

CommonString
____________
.. autoclass:: pyderasn.CommonString

NumericString
_____________
.. autoclass:: pyderasn.NumericString

PrintableString
_______________
.. autoclass:: pyderasn.PrintableString
   :members: __init__, allow_asterisk, allow_ampersand

IA5String
_________
.. autoclass:: pyderasn.IA5String

VisibleString
_____________
.. autoclass:: pyderasn.VisibleString

UTCTime
_______
.. autoclass:: pyderasn.UTCTime
   :members: __init__, todatetime, totzdatetime

GeneralizedTime
_______________
.. autoclass:: pyderasn.GeneralizedTime
   :members: __init__, todatetime, totzdatetime

Special types
-------------

Choice
______
.. autoclass:: pyderasn.Choice
   :members: __init__, choice, value

PrimitiveTypes
______________
.. autoclass:: PrimitiveTypes

Any
___
.. autoclass:: pyderasn.Any
   :members: __init__

Constructed types
-----------------

Sequence
________
.. autoclass:: pyderasn.Sequence
   :members: __init__

Set
___
.. autoclass:: pyderasn.Set
   :members: __init__

SequenceOf
__________
.. autoclass:: pyderasn.SequenceOf
   :members: __init__

SetOf
_____
.. autoclass:: pyderasn.SetOf
   :members: __init__

Various
-------

.. autofunction:: pyderasn.abs_decode_path
.. autofunction:: pyderasn.agg_octet_string
.. autofunction:: pyderasn.ascii_visualize
.. autofunction:: pyderasn.colonize_hex
.. autofunction:: pyderasn.encode2pass
.. autofunction:: pyderasn.encode_cer
.. autofunction:: pyderasn.file_mmaped
.. autofunction:: pyderasn.hexenc
.. autofunction:: pyderasn.hexdec
.. autofunction:: pyderasn.hexdump
.. autofunction:: pyderasn.tag_encode
.. autofunction:: pyderasn.tag_decode
.. autofunction:: pyderasn.tag_ctxp
.. autofunction:: pyderasn.tag_ctxc
.. autoclass:: pyderasn.DecodeError
   :members: __init__
.. autoclass:: pyderasn.NotEnoughData
.. autoclass:: pyderasn.ExceedingData
.. autoclass:: pyderasn.LenIndefForm
.. autoclass:: pyderasn.TagMismatch
.. autoclass:: pyderasn.InvalidLength
.. autoclass:: pyderasn.InvalidOID
.. autoclass:: pyderasn.ObjUnknown
.. autoclass:: pyderasn.ObjNotReady
.. autoclass:: pyderasn.InvalidValueType
.. autoclass:: pyderasn.BoundsError

.. _cmdline:

Command-line usage
------------------

You can decode DER/BER files using command line abilities::

    $ python -m pyderasn --schema tests.test_crts:Certificate path/to/file

If there is no schema for your file, then you can try parsing it without,
but of course IMPLICIT tags will often make it impossible. But result is
good enough for the certificate above::

    $ python -m pyderasn path/to/file
        0   [1,3,1604]  . >: SEQUENCE OF
        4   [1,3,1453]  . . >: SEQUENCE OF
        8   [0,0,   5]  . . . . >: [0] ANY
                        . . . . . A0:03:02:01:02
       13   [1,1,   3]  . . . . >: INTEGER 61595
       18   [1,1,  13]  . . . . >: SEQUENCE OF
       20   [1,1,   9]  . . . . . . >: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
       31   [1,1,   0]  . . . . . . >: NULL
       33   [1,3, 274]  . . . . >: SEQUENCE OF
       37   [1,1,  11]  . . . . . . >: SET OF
       39   [1,1,   9]  . . . . . . . . >: SEQUENCE OF
       41   [1,1,   3]  . . . . . . . . . . >: OBJECT IDENTIFIER 2.5.4.6
       46   [1,1,   2]  . . . . . . . . . . >: PrintableString PrintableString ES
    [...]
     1409   [1,1,  50]  . . . . . . >: SEQUENCE OF
     1411   [1,1,   8]  . . . . . . . . >: OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.1
     1421   [1,1,  38]  . . . . . . . . >: OCTET STRING 38 bytes
                        . . . . . . . . . 30:24:30:22:06:08:2B:06:01:05:05:07:30:01:86:16
                        . . . . . . . . . 68:74:74:70:3A:2F:2F:6F:63:73:70:2E:69:70:73:63
                        . . . . . . . . . 61:2E:63:6F:6D:2F
     1461   [1,1,  13]  . . >: SEQUENCE OF
     1463   [1,1,   9]  . . . . >: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
     1474   [1,1,   0]  . . . . >: NULL
     1476   [1,2, 129]  . . >: BIT STRING 1024 bits
                        . . . 68:EE:79:97:97:DD:3B:EF:16:6A:06:F2:14:9A:6E:CD
                        . . . 9E:12:F7:AA:83:10:BD:D1:7C:98:FA:C7:AE:D4:0E:2C
    [...]

Human readable OIDs
___________________

If you have got dictionaries with ObjectIdentifiers, like example one
from ``tests/test_crts.py``::

    stroid2name = {
        "1.2.840.113549.1.1.1": "id-rsaEncryption",
        "1.2.840.113549.1.1.5": "id-sha1WithRSAEncryption",
        [...]
        "2.5.4.10": "id-at-organizationName",
        "2.5.4.11": "id-at-organizationalUnitName",
    }

then you can pass it to pretty printer to see human readable OIDs::

    $ python -m pyderasn --oids tests.test_crts:stroid2name path/to/file
    [...]
       37   [1,1,  11]  . . . . . . >: SET OF
       39   [1,1,   9]  . . . . . . . . >: SEQUENCE OF
       41   [1,1,   3]  . . . . . . . . . . >: OBJECT IDENTIFIER id-at-countryName (2.5.4.6)
       46   [1,1,   2]  . . . . . . . . . . >: PrintableString PrintableString ES
       50   [1,1,  18]  . . . . . . >: SET OF
       52   [1,1,  16]  . . . . . . . . >: SEQUENCE OF
       54   [1,1,   3]  . . . . . . . . . . >: OBJECT IDENTIFIER id-at-stateOrProvinceName (2.5.4.8)
       59   [1,1,   9]  . . . . . . . . . . >: PrintableString PrintableString Barcelona
       70   [1,1,  18]  . . . . . . >: SET OF
       72   [1,1,  16]  . . . . . . . . >: SEQUENCE OF
       74   [1,1,   3]  . . . . . . . . . . >: OBJECT IDENTIFIER id-at-localityName (2.5.4.7)
       79   [1,1,   9]  . . . . . . . . . . >: PrintableString PrintableString Barcelona
    [...]

Decode paths
____________

Each decoded element has so-called decode path: sequence of structure
names it is passing during the decode process. Each element has its own
unique path inside the whole ASN.1 tree. You can print it out with
``--print-decode-path`` option::

    $ python -m pyderasn --schema path.to:Certificate --print-decode-path path/to/file
       0    [1,3,1604]  Certificate SEQUENCE []
       4    [1,3,1453]   . tbsCertificate: TBSCertificate SEQUENCE [tbsCertificate]
      10-2  [1,1,   1]   . . version: [0] EXPLICIT Version INTEGER v3 OPTIONAL [tbsCertificate:version]
      13    [1,1,   3]   . . serialNumber: CertificateSerialNumber INTEGER 61595 [tbsCertificate:serialNumber]
      18    [1,1,  13]   . . signature: AlgorithmIdentifier SEQUENCE [tbsCertificate:signature]
      20    [1,1,   9]   . . . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.5 [tbsCertificate:signature:algorithm]
      31    [0,0,   2]   . . . parameters: [UNIV 5] ANY OPTIONAL [tbsCertificate:signature:parameters]
                         . . . . 05:00
      33    [0,0, 278]   . . issuer: Name CHOICE rdnSequence [tbsCertificate:issuer]
      33    [1,3, 274]   . . . rdnSequence: RDNSequence SEQUENCE OF [tbsCertificate:issuer:rdnSequence]
      37    [1,1,  11]   . . . . 0: RelativeDistinguishedName SET OF [tbsCertificate:issuer:rdnSequence:0]
      39    [1,1,   9]   . . . . . 0: AttributeTypeAndValue SEQUENCE [tbsCertificate:issuer:rdnSequence:0:0]
      41    [1,1,   3]   . . . . . . type: AttributeType OBJECT IDENTIFIER 2.5.4.6 [tbsCertificate:issuer:rdnSequence:0:0:type]
      46    [0,0,   4]   . . . . . . value: [UNIV 19] AttributeValue ANY [tbsCertificate:issuer:rdnSequence:0:0:value]
                         . . . . . . . 13:02:45:53
      46    [1,1,   2]   . . . . . . . DEFINED BY 2.5.4.6: CountryName PrintableString ES [tbsCertificate:issuer:rdnSequence:0:0:value:DEFINED BY 2.5.4.6]
    [...]

Now you can print only the specified tree, for example signature algorithm::

    $ python -m pyderasn --schema path.to:Certificate --decode-path-only tbsCertificate:signature path/to/file
      18    [1,1,  13]  AlgorithmIdentifier SEQUENCE
      20    [1,1,   9]   . algorithm: OBJECT IDENTIFIER 1.2.840.113549.1.1.5
      31    [0,0,   2]   . parameters: [UNIV 5] ANY OPTIONAL
                         . . 05:00
"""

from array import array
from collections import namedtuple
from collections import OrderedDict
from copy import copy
from datetime import datetime
from datetime import timedelta
from io import BytesIO
from math import ceil
from operator import attrgetter
from string import ascii_letters
from string import digits
from struct import Struct as struct_Struct
from sys import maxsize as sys_maxsize
from sys import version_info
from unicodedata import category as unicat

try:
    from termcolor import colored
except ImportError:  # pragma: no cover
    def colored(what, *args, **kwargs):
        return what

try:
    from dateutil.tz import UTC as tzUTC
except ImportError:  # pragma: no cover
    tzUTC = "missing"


__version__ = "9.3"

__all__ = (
    "agg_octet_string",
    "Any",
    "BitString",
    "BMPString",
    "Boolean",
    "BoundsError",
    "Choice",
    "colonize_hex",
    "DecodeError",
    "DecodePathDefBy",
    "encode2pass",
    "encode_cer",
    "Enumerated",
    "ExceedingData",
    "file_mmaped",
    "GeneralizedTime",
    "GeneralString",
    "GraphicString",
    "hexdec",
    "hexenc",
    "IA5String",
    "Integer",
    "InvalidLength",
    "InvalidOID",
    "InvalidValueType",
    "ISO646String",
    "LenIndefForm",
    "NotEnoughData",
    "Null",
    "NumericString",
    "obj_by_path",
    "ObjectIdentifier",
    "ObjNotReady",
    "ObjUnknown",
    "OctetString",
    "PrimitiveTypes",
    "PrintableString",
    "Sequence",
    "SequenceOf",
    "Set",
    "SetOf",
    "T61String",
    "tag_ctxc",
    "tag_ctxp",
    "tag_decode",
    "TagClassApplication",
    "TagClassContext",
    "TagClassPrivate",
    "TagClassUniversal",
    "TagFormConstructed",
    "TagFormPrimitive",
    "TagMismatch",
    "TeletexString",
    "UniversalString",
    "UTCTime",
    "UTF8String",
    "VideotexString",
    "VisibleString",
)

TagClassUniversal = 0
TagClassApplication = 1 << 6
TagClassContext = 1 << 7
TagClassPrivate = 1 << 6 | 1 << 7
TagFormPrimitive = 0
TagFormConstructed = 1 << 5
TagClassReprs = {
    TagClassContext: "",
    TagClassApplication: "APPLICATION ",
    TagClassPrivate: "PRIVATE ",
    TagClassUniversal: "UNIV ",
}
EOC = b"\x00\x00"
EOC_LEN = len(EOC)
LENINDEF = b"\x80"  # length indefinite mark
LENINDEF_PP_CHAR = "∞"
NAMEDTUPLE_KWARGS = {} if version_info < (3, 6) else {"module": __name__}
SET01 = frozenset("01")
DECIMALS = frozenset(digits)
DECIMAL_SIGNS = ".,"
NEXT_ATTR_NAME = "__next__"


def file_mmaped(fd):
    """Make mmap-ed memoryview for reading from file

    :param fd: file object
    :returns: memoryview over read-only mmap-ing of the whole file

    .. warning::

       It does not work under Windows.
    """
    import mmap
    return memoryview(mmap.mmap(fd.fileno(), length=0, prot=mmap.PROT_READ))


def pureint(value):
    if not set(value) <= DECIMALS:
        raise ValueError("non-pure integer")
    return int(value)


def fractions2float(fractions_raw):
    pureint(fractions_raw)
    return float("0." + fractions_raw)


def get_def_by_path(defines_by_path, sub_decode_path):
    """Get define by decode path
    """
    for path, define in defines_by_path:
        if len(path) != len(sub_decode_path):
            continue
        for p1, p2 in zip(path, sub_decode_path):
            if (p1 is not any) and (p1 != p2):
                break
        else:
            return define


########################################################################
# Errors
########################################################################

class ASN1Error(ValueError):
    pass


class DecodeError(ASN1Error):
    def __init__(self, msg="", klass=None, decode_path=(), offset=0):
        """
        :param str msg: reason of decode failing
        :param klass: optional exact DecodeError inherited class (like
                      :py:exc:`NotEnoughData`, :py:exc:`TagMismatch`,
                      :py:exc:`InvalidLength`)
        :param decode_path: tuple of strings. It contains human
                            readable names of the fields through which
                            decoding process has passed
        :param int offset: binary offset where failure happened
        """
        super().__init__()
        self.msg = msg
        self.klass = klass
        self.decode_path = decode_path
        self.offset = offset

    def __str__(self):
        return " ".join(
            c for c in (
                "" if self.klass is None else self.klass.__name__,
                (
                    ("(%s)" % ":".join(str(dp) for dp in self.decode_path))
                    if len(self.decode_path) > 0 else ""
                ),
                ("(at %d)" % self.offset) if self.offset > 0 else "",
                self.msg,
            ) if c != ""
        )

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


class NotEnoughData(DecodeError):
    pass


class ExceedingData(ASN1Error):
    def __init__(self, nbytes):
        super().__init__()
        self.nbytes = nbytes

    def __str__(self):
        return "%d trailing bytes" % self.nbytes

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


class LenIndefForm(DecodeError):
    pass


class TagMismatch(DecodeError):
    pass


class InvalidLength(DecodeError):
    pass


class InvalidOID(DecodeError):
    pass


class ObjUnknown(ASN1Error):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def __str__(self):
        return "object is unknown: %s" % self.name

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


class ObjNotReady(ASN1Error):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def __str__(self):
        return "object is not ready: %s" % self.name

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


class InvalidValueType(ASN1Error):
    def __init__(self, expected_types):
        super().__init__()
        self.expected_types = expected_types

    def __str__(self):
        return "invalid value type, expected: %s" % ", ".join(
            [repr(t) for t in self.expected_types]
        )

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


class BoundsError(ASN1Error):
    def __init__(self, bound_min, value, bound_max):
        super().__init__()
        self.bound_min = bound_min
        self.value = value
        self.bound_max = bound_max

    def __str__(self):
        return "unsatisfied bounds: %s <= %s <= %s" % (
            self.bound_min,
            self.value,
            self.bound_max,
        )

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self)


########################################################################
# Basic coders
########################################################################

def hexdec(data):
    """Binary data to hexadecimal string convert
    """
    return bytes.fromhex(data)


def hexenc(data):
    """Hexadecimal string to binary data convert
    """
    return data.hex()


def int_bytes_len(num, byte_len=8):
    if num == 0:
        return 1
    return int(ceil(float(num.bit_length()) / byte_len))


def zero_ended_encode(num):
    octets = bytearray(int_bytes_len(num, 7))
    i = len(octets) - 1
    octets[i] = num & 0x7F
    num >>= 7
    i -= 1
    while num > 0:
        octets[i] = 0x80 | (num & 0x7F)
        num >>= 7
        i -= 1
    return bytes(octets)


int2byte = struct_Struct(">B").pack


def tag_encode(num, klass=TagClassUniversal, form=TagFormPrimitive):
    """Encode tag to binary form

    :param int num: tag's number
    :param int klass: tag's class (:py:data:`pyderasn.TagClassUniversal`,
                      :py:data:`pyderasn.TagClassContext`,
                      :py:data:`pyderasn.TagClassApplication`,
                      :py:data:`pyderasn.TagClassPrivate`)
    :param int form: tag's form (:py:data:`pyderasn.TagFormPrimitive`,
                     :py:data:`pyderasn.TagFormConstructed`)
    """
    if num < 31:
        # [XX|X|.....]
        return int2byte(klass | form | num)
    # [XX|X|11111][1.......][1.......] ... [0.......]
    return int2byte(klass | form | 31) + zero_ended_encode(num)


def tag_decode(tag):
    """Decode tag from binary form

    .. warning::

       No validation is performed, assuming that it has already passed.

    It returns tuple with three integers, as
    :py:func:`pyderasn.tag_encode` accepts.
    """
    first_octet = tag[0]
    klass = first_octet & 0xC0
    form = first_octet & 0x20
    if first_octet & 0x1F < 0x1F:
        return (klass, form, first_octet & 0x1F)
    num = 0
    for octet in tag[1:]:
        num <<= 7
        num |= octet & 0x7F
    return (klass, form, num)


def tag_ctxp(num):
    """Create CONTEXT PRIMITIVE tag
    """
    return tag_encode(num=num, klass=TagClassContext, form=TagFormPrimitive)


def tag_ctxc(num):
    """Create CONTEXT CONSTRUCTED tag
    """
    return tag_encode(num=num, klass=TagClassContext, form=TagFormConstructed)


def tag_strip(data):
    """Take off tag from the data

    :returns: (encoded tag, tag length, remaining data)
    """
    if len(data) == 0:
        raise NotEnoughData("no data at all")
    if data[0] & 0x1F < 31:
        return data[:1], 1, data[1:]
    i = 0
    while True:
        i += 1
        if i == len(data):
            raise DecodeError("unfinished tag")
        if data[i] & 0x80 == 0:
            break
    if i == 1 and data[1] < 0x1F:
        raise DecodeError("unexpected long form")
    if i > 1 and data[1] & 0x7F == 0:
        raise DecodeError("leading zero byte in tag value")
    i += 1
    return data[:i], i, data[i:]


def len_encode(l):
    if l < 0x80:
        return int2byte(l)
    octets = bytearray(int_bytes_len(l) + 1)
    octets[0] = 0x80 | (len(octets) - 1)
    for i in range(len(octets) - 1, 0, -1):
        octets[i] = l & 0xFF
        l >>= 8
    return bytes(octets)


def len_decode(data):
    """Decode length

    :returns: (decoded length, length's length, remaining data)
    :raises LenIndefForm: if indefinite form encoding is met
    """
    if len(data) == 0:
        raise NotEnoughData("no data at all")
    first_octet = data[0]
    if first_octet & 0x80 == 0:
        return first_octet, 1, data[1:]
    octets_num = first_octet & 0x7F
    if octets_num + 1 > len(data):
        raise NotEnoughData("encoded length is longer than data")
    if octets_num == 0:
        raise LenIndefForm()
    if data[1] == 0:
        raise DecodeError("leading zeros")
    l = 0
    for v in data[1:1 + octets_num]:
        l = (l << 8) | v
    if l <= 127:
        raise DecodeError("long form instead of short one")
    return l, 1 + octets_num, data[1 + octets_num:]


LEN0 = len_encode(0)
LEN1 = len_encode(1)
LEN1K = len_encode(1000)


def len_size(l):
    """How many bytes length field will take
    """
    if l < 128:
        return 1
    if l < 256:  # 1 << 8
        return 2
    if l < 65536:  # 1 << 16
        return 3
    if l < 16777216:  # 1 << 24
        return 4
    if l < 4294967296:  # 1 << 32
        return 5
    if l < 1099511627776:  # 1 << 40
        return 6
    if l < 281474976710656:  # 1 << 48
        return 7
    if l < 72057594037927936:  # 1 << 56
        return 8
    raise OverflowError("too big length")


def write_full(writer, data):
    """Fully write provided data

    :param writer: must comply with ``io.RawIOBase.write`` behaviour

    BytesIO does not guarantee that the whole data will be written at
    once. That function write everything provided, raising an error if
    ``writer`` returns None.
    """
    data = memoryview(data)
    written = 0
    while written != len(data):
        n = writer(data[written:])
        if n is None:
            raise ValueError("can not write to buf")
        written += n


# If it is 64-bit system, then use compact 64-bit array of unsigned
# longs. Use an ordinary list with universal integers otherwise, that
# is slower.
if sys_maxsize > 2 ** 32:
    def state_2pass_new():
        return array("L")
else:
    def state_2pass_new():
        return []


########################################################################
# Base class
########################################################################

class AutoAddSlots(type):
    def __new__(cls, name, bases, _dict):
        _dict["__slots__"] = _dict.get("__slots__", ())
        return super().__new__(cls, name, bases, _dict)


BasicState = namedtuple("BasicState", (
    "version",
    "tag",
    "tag_order",
    "expl",
    "default",
    "optional",
    "offset",
    "llen",
    "vlen",
    "expl_lenindef",
    "lenindef",
    "ber_encoded",
), **NAMEDTUPLE_KWARGS)


class Obj(metaclass=AutoAddSlots):
    """Common ASN.1 object class

    All ASN.1 types are inherited from it. It has metaclass that
    automatically adds ``__slots__`` to all inherited classes.
    """
    __slots__ = (
        "tag",
        "_tag_order",
        "_value",
        "_expl",
        "default",
        "optional",
        "offset",
        "llen",
        "vlen",
        "expl_lenindef",
        "lenindef",
        "ber_encoded",
    )

    def __init__(
            self,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        self.tag = getattr(self, "impl", self.tag_default) if impl is None else impl
        self._expl = getattr(self, "expl", None) if expl is None else expl
        if self.tag != self.tag_default and self._expl is not None:
            raise ValueError("implicit and explicit tags can not be set simultaneously")
        if self.tag is None:
            self._tag_order = None
        else:
            tag_class, _, tag_num = tag_decode(
                self.tag if self._expl is None else self._expl
            )
            self._tag_order = (tag_class, tag_num)
        if default is not None:
            optional = True
        self.optional = optional
        self.offset, self.llen, self.vlen = _decoded
        self.default = None
        self.expl_lenindef = False
        self.lenindef = False
        self.ber_encoded = False

    @property
    def ready(self):  # pragma: no cover
        """Is object ready to be encoded?
        """
        raise NotImplementedError()

    def _assert_ready(self):
        if not self.ready:
            raise ObjNotReady(self.__class__.__name__)

    @property
    def bered(self):
        """Is either object or any elements inside is BER encoded?
        """
        return self.expl_lenindef or self.lenindef or self.ber_encoded

    @property
    def decoded(self):
        """Is object decoded?
        """
        return (self.llen + self.vlen) > 0

    def __getstate__(self):  # pragma: no cover
        """Used for making safe to be mutable pickleable copies
        """
        raise NotImplementedError()

    def __setstate__(self, state):
        if state.version != __version__:
            raise ValueError("data is pickled by different PyDERASN version")
        self.tag = state.tag
        self._tag_order = state.tag_order
        self._expl = state.expl
        self.default = state.default
        self.optional = state.optional
        self.offset = state.offset
        self.llen = state.llen
        self.vlen = state.vlen
        self.expl_lenindef = state.expl_lenindef
        self.lenindef = state.lenindef
        self.ber_encoded = state.ber_encoded

    @property
    def tag_order(self):
        """Tag's (class, number) used for DER/CER sorting
        """
        return self._tag_order

    @property
    def tag_order_cer(self):
        return self.tag_order

    @property
    def tlen(self):
        """.. seealso:: :ref:`decoding`
        """
        return len(self.tag)

    @property
    def tlvlen(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.tlen + self.llen + self.vlen

    def __str__(self):  # pragma: no cover
        return self.__unicode__()

    def __ne__(self, their):
        return not(self == their)

    def __gt__(self, their):  # pragma: no cover
        return not(self < their)

    def __le__(self, their):  # pragma: no cover
        return (self == their) or (self < their)

    def __ge__(self, their):  # pragma: no cover
        return (self == their) or (self > their)

    def _encode(self):  # pragma: no cover
        raise NotImplementedError()

    def _encode_cer(self, writer):
        write_full(writer, self._encode())

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):  # pragma: no cover
        yield NotImplemented

    def _encode1st(self, state):
        raise NotImplementedError()

    def _encode2nd(self, writer, state_iter):
        raise NotImplementedError()

    def encode(self):
        """DER encode the structure

        :returns: DER representation
        """
        raw = self._encode()
        if self._expl is None:
            return raw
        return b"".join((self._expl, len_encode(len(raw)), raw))

    def encode1st(self, state=None):
        """Do the 1st pass of 2-pass encoding

        :rtype: (int, array("L"))
        :returns: full length of encoded data and precalculated various
                  objects lengths
        """
        if state is None:
            state = state_2pass_new()
        if self._expl is None:
            return self._encode1st(state)
        state.append(0)
        idx = len(state) - 1
        vlen, _ = self._encode1st(state)
        state[idx] = vlen
        fulllen = len(self._expl) + len_size(vlen) + vlen
        return fulllen, state

    def encode2nd(self, writer, state_iter):
        """Do the 2nd pass of 2-pass encoding

        :param writer: must comply with ``io.RawIOBase.write`` behaviour
        :param state_iter: iterator over the 1st pass state (``iter(state)``)
        """
        if self._expl is None:
            self._encode2nd(writer, state_iter)
        else:
            write_full(writer, self._expl + len_encode(next(state_iter)))
            self._encode2nd(writer, state_iter)

    def encode_cer(self, writer):
        """CER encode the structure to specified writer

        :param writer: must comply with ``io.RawIOBase.write``
                       behaviour. It takes slice to be written and
                       returns number of bytes processed. If it returns
                       None, then exception will be raised
        """
        if self._expl is not None:
            write_full(writer, self._expl + LENINDEF)
        if getattr(self, "der_forced", False):
            write_full(writer, self._encode())
        else:
            self._encode_cer(writer)
        if self._expl is not None:
            write_full(writer, EOC)

    def hexencode(self):
        """Do hexadecimal encoded :py:meth:`pyderasn.Obj.encode`
        """
        return hexenc(self.encode())

    def decode(
            self,
            data,
            offset=0,
            leavemm=False,
            decode_path=(),
            ctx=None,
            tag_only=False,
            _ctx_immutable=True,
    ):
        """Decode the data

        :param data: either binary or memoryview
        :param int offset: initial data's offset
        :param bool leavemm: do we need to leave memoryview of remaining
                    data as is, or convert it to bytes otherwise
        :param decode_path: current decode path (tuples of strings,
                            possibly with DecodePathDefBy) with will be
                            the root for all underlying objects
        :param ctx: optional :ref:`context <ctx>` governing decoding process
        :param bool tag_only: decode only the tag, without length and
                              contents (used only in Choice and Set
                              structures, trying to determine if tag satisfies
                              the schema)
        :param bool _ctx_immutable: do we need to ``copy.copy()`` ``ctx``
                                    before using it?
        :returns: (Obj, remaining data)

        .. seealso:: :ref:`decoding`
        """
        result = next(self.decode_evgen(
            data,
            offset,
            leavemm,
            decode_path,
            ctx,
            tag_only,
            _ctx_immutable,
            _evgen_mode=False,
        ))
        if result is None:
            return None
        _, obj, tail = result
        return obj, tail

    def decode_evgen(
            self,
            data,
            offset=0,
            leavemm=False,
            decode_path=(),
            ctx=None,
            tag_only=False,
            _ctx_immutable=True,
            _evgen_mode=True,
    ):
        """Decode with evgen mode on

        That method is identical to :py:meth:`pyderasn.Obj.decode`, but
        it returns the generator producing ``(decode_path, obj, tail)``
        values.
        .. seealso:: :ref:`evgen mode <evgen_mode>`.
        """
        if ctx is None:
            ctx = {}
        elif _ctx_immutable:
            ctx = copy(ctx)
        tlv = memoryview(data)
        if (
                _evgen_mode and
                get_def_by_path(ctx.get("evgen_mode_upto", ()), decode_path) is not None
        ):
            _evgen_mode = False
        if self._expl is None:
            for result in self._decode(
                    tlv,
                    offset=offset,
                    decode_path=decode_path,
                    ctx=ctx,
                    tag_only=tag_only,
                    evgen_mode=_evgen_mode,
            ):
                if tag_only:
                    yield None
                    return
                _decode_path, obj, tail = result
                if _decode_path is not decode_path:
                    yield result
        else:
            try:
                t, tlen, lv = tag_strip(tlv)
            except DecodeError as err:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if t != self._expl:
                raise TagMismatch(
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            try:
                l, llen, v = len_decode(lv)
            except LenIndefForm as err:
                if not ctx.get("bered", False):
                    raise err.__class__(
                        msg=err.msg,
                        klass=self.__class__,
                        decode_path=decode_path,
                        offset=offset,
                    )
                llen, v = 1, lv[1:]
                offset += tlen + llen
                for result in self._decode(
                        v,
                        offset=offset,
                        decode_path=decode_path,
                        ctx=ctx,
                        tag_only=tag_only,
                        evgen_mode=_evgen_mode,
                ):
                    if tag_only:  # pragma: no cover
                        yield None
                        return
                    _decode_path, obj, tail = result
                    if _decode_path is not decode_path:
                        yield result
                eoc_expected, tail = tail[:EOC_LEN], tail[EOC_LEN:]
                if eoc_expected.tobytes() != EOC:
                    raise DecodeError(
                        "no EOC",
                        klass=self.__class__,
                        decode_path=decode_path,
                        offset=offset,
                    )
                obj.vlen += EOC_LEN
                obj.expl_lenindef = True
            except DecodeError as err:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            else:
                if l > len(v):
                    raise NotEnoughData(
                        "encoded length is longer than data",
                        klass=self.__class__,
                        decode_path=decode_path,
                        offset=offset,
                    )
                for result in self._decode(
                        v,
                        offset=offset + tlen + llen,
                        decode_path=decode_path,
                        ctx=ctx,
                        tag_only=tag_only,
                        evgen_mode=_evgen_mode,
                ):
                    if tag_only:  # pragma: no cover
                        yield None
                        return
                    _decode_path, obj, tail = result
                    if _decode_path is not decode_path:
                        yield result
                if obj.tlvlen < l and not ctx.get("allow_expl_oob", False):
                    raise DecodeError(
                        "explicit tag out-of-bound, longer than data",
                        klass=self.__class__,
                        decode_path=decode_path,
                        offset=offset,
                    )
        yield decode_path, obj, (tail if leavemm else tail.tobytes())

    def decod(self, data, offset=0, decode_path=(), ctx=None):
        """Decode the data, check that tail is empty

        :raises ExceedingData: if tail is not empty

        This is just a wrapper over :py:meth:`pyderasn.Obj.decode`
        (decode without tail) that also checks that there is no
        trailing data left.
        """
        obj, tail = self.decode(
            data,
            offset=offset,
            decode_path=decode_path,
            ctx=ctx,
            leavemm=True,
        )
        if len(tail) > 0:
            raise ExceedingData(len(tail))
        return obj

    def hexdecode(self, data, *args, **kwargs):
        """Do :py:meth:`pyderasn.Obj.decode` with hexadecimal decoded data
        """
        return self.decode(hexdec(data), *args, **kwargs)

    def hexdecod(self, data, *args, **kwargs):
        """Do :py:meth:`pyderasn.Obj.decod` with hexadecimal decoded data
        """
        return self.decod(hexdec(data), *args, **kwargs)

    @property
    def expled(self):
        """.. seealso:: :ref:`decoding`
        """
        return self._expl is not None

    @property
    def expl_tag(self):
        """.. seealso:: :ref:`decoding`
        """
        return self._expl

    @property
    def expl_tlen(self):
        """.. seealso:: :ref:`decoding`
        """
        return len(self._expl)

    @property
    def expl_llen(self):
        """.. seealso:: :ref:`decoding`
        """
        if self.expl_lenindef:
            return 1
        return len(len_encode(self.tlvlen))

    @property
    def expl_offset(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.offset - self.expl_tlen - self.expl_llen

    @property
    def expl_vlen(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.tlvlen

    @property
    def expl_tlvlen(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.expl_tlen + self.expl_llen + self.expl_vlen

    @property
    def fulloffset(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.expl_offset if self.expled else self.offset

    @property
    def fulllen(self):
        """.. seealso:: :ref:`decoding`
        """
        return self.expl_tlvlen if self.expled else self.tlvlen

    def pps_lenindef(self, decode_path):
        if self.lenindef and not (
                getattr(self, "defined", None) is not None and
                self.defined[1].lenindef
        ):
            yield _pp(
                asn1_type_name="EOC",
                obj_name="",
                decode_path=decode_path,
                offset=(
                    self.offset + self.tlvlen -
                    (EOC_LEN * 2 if self.expl_lenindef else EOC_LEN)
                ),
                tlen=1,
                llen=1,
                vlen=0,
                ber_encoded=True,
                bered=True,
            )
        if self.expl_lenindef:
            yield _pp(
                asn1_type_name="EOC",
                obj_name="EXPLICIT",
                decode_path=decode_path,
                offset=self.expl_offset + self.expl_tlvlen - EOC_LEN,
                tlen=1,
                llen=1,
                vlen=0,
                ber_encoded=True,
                bered=True,
            )


def encode_cer(obj):
    """Encode to CER in memory buffer

    :returns bytes: memory buffer contents
    """
    buf = BytesIO()
    obj.encode_cer(buf.write)
    return buf.getvalue()


def encode2pass(obj):
    """Encode (2-pass mode) to DER in memory buffer

    :returns bytes: memory buffer contents
    """
    buf = BytesIO()
    _, state = obj.encode1st()
    obj.encode2nd(buf.write, iter(state))
    return buf.getvalue()


class DecodePathDefBy:
    """DEFINED BY representation inside decode path
    """
    __slots__ = ("defined_by",)

    def __init__(self, defined_by):
        self.defined_by = defined_by

    def __ne__(self, their):
        return not(self == their)

    def __eq__(self, their):
        if not isinstance(their, self.__class__):
            return False
        return self.defined_by == their.defined_by

    def __str__(self):
        return "DEFINED BY " + str(self.defined_by)

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.defined_by)


########################################################################
# Pretty printing
########################################################################

PP = namedtuple("PP", (
    "obj",
    "asn1_type_name",
    "obj_name",
    "decode_path",
    "value",
    "blob",
    "optional",
    "default",
    "impl",
    "expl",
    "offset",
    "tlen",
    "llen",
    "vlen",
    "expl_offset",
    "expl_tlen",
    "expl_llen",
    "expl_vlen",
    "expl_lenindef",
    "lenindef",
    "ber_encoded",
    "bered",
), **NAMEDTUPLE_KWARGS)


def _pp(
        obj=None,
        asn1_type_name="unknown",
        obj_name="unknown",
        decode_path=(),
        value=None,
        blob=None,
        optional=False,
        default=False,
        impl=None,
        expl=None,
        offset=0,
        tlen=0,
        llen=0,
        vlen=0,
        expl_offset=None,
        expl_tlen=None,
        expl_llen=None,
        expl_vlen=None,
        expl_lenindef=False,
        lenindef=False,
        ber_encoded=False,
        bered=False,
):
    return PP(
        obj,
        asn1_type_name,
        obj_name,
        decode_path,
        value,
        blob,
        optional,
        default,
        impl,
        expl,
        offset,
        tlen,
        llen,
        vlen,
        expl_offset,
        expl_tlen,
        expl_llen,
        expl_vlen,
        expl_lenindef,
        lenindef,
        ber_encoded,
        bered,
    )


def _colourize(what, colour, with_colours, attrs=("bold",)):
    return colored(what, colour, attrs=attrs) if with_colours else what


def colonize_hex(hexed):
    """Separate hexadecimal string with colons
    """
    return ":".join(hexed[i:i + 2] for i in range(0, len(hexed), 2))


def find_oid_name(asn1_type_name, oid_maps, value):
    if len(oid_maps) > 0 and asn1_type_name == ObjectIdentifier.asn1_type_name:
        for oid_map in oid_maps:
            oid_name = oid_map.get(value)
            if oid_name is not None:
                return oid_name
    return None


def pp_console_row(
        pp,
        oid_maps=(),
        with_offsets=False,
        with_blob=True,
        with_colours=False,
        with_decode_path=False,
        decode_path_len_decrease=0,
):
    cols = []
    if with_offsets:
        col = "%5d%s%s" % (
            pp.offset,
            (
                "  " if pp.expl_offset is None else
                ("-%d" % (pp.offset - pp.expl_offset))
            ),
            LENINDEF_PP_CHAR if pp.expl_lenindef else " ",
        )
        col = _colourize(col, "red", with_colours, ())
        col += _colourize("B", "red", with_colours) if pp.bered else " "
        cols.append(col)
        col = "[%d,%d,%4d]%s" % (
            pp.tlen, pp.llen, pp.vlen,
            LENINDEF_PP_CHAR if pp.lenindef else " "
        )
        col = _colourize(col, "green", with_colours, ())
        cols.append(col)
    decode_path_len = len(pp.decode_path) - decode_path_len_decrease
    if decode_path_len > 0:
        cols.append(" ." * decode_path_len)
        ent = pp.decode_path[-1]
        if isinstance(ent, DecodePathDefBy):
            cols.append(_colourize("DEFINED BY", "red", with_colours, ("reverse",)))
            value = str(ent.defined_by)
            oid_name = find_oid_name(ent.defined_by.asn1_type_name, oid_maps, value)
            if oid_name is None:
                cols.append(_colourize("%s:" % value, "white", with_colours, ("reverse",)))
            else:
                cols.append(_colourize("%s:" % oid_name, "green", with_colours))
        else:
            cols.append(_colourize("%s:" % ent, "yellow", with_colours, ("reverse",)))
    if pp.expl is not None:
        klass, _, num = pp.expl
        col = "[%s%d] EXPLICIT" % (TagClassReprs[klass], num)
        cols.append(_colourize(col, "blue", with_colours))
    if pp.impl is not None:
        klass, _, num = pp.impl
        col = "[%s%d]" % (TagClassReprs[klass], num)
        cols.append(_colourize(col, "blue", with_colours))
    if pp.asn1_type_name.replace(" ", "") != pp.obj_name.upper():
        cols.append(_colourize(pp.obj_name, "magenta", with_colours))
    if pp.ber_encoded:
        cols.append(_colourize("BER", "red", with_colours))
    cols.append(_colourize(pp.asn1_type_name, "cyan", with_colours))
    if pp.value is not None:
        value = pp.value
        cols.append(_colourize(value, "white", with_colours, ("reverse",)))
        oid_name = find_oid_name(pp.asn1_type_name, oid_maps, pp.value)
        if oid_name is not None:
            cols.append(_colourize("(%s)" % oid_name, "green", with_colours))
        if pp.asn1_type_name == Integer.asn1_type_name:
            cols.append(_colourize(
                "(%s)" % colonize_hex(pp.obj.tohex()), "green", with_colours,
            ))
    if with_blob:
        if pp.blob.__class__ == bytes:
            cols.append(hexenc(pp.blob))
        elif pp.blob.__class__ == tuple:
            cols.append(", ".join(pp.blob))
    if pp.optional:
        cols.append(_colourize("OPTIONAL", "red", with_colours))
    if pp.default:
        cols.append(_colourize("DEFAULT", "red", with_colours))
    if with_decode_path:
        cols.append(_colourize(
            "[%s]" % ":".join(str(p) for p in pp.decode_path),
            "grey",
            with_colours,
        ))
    return " ".join(cols)


def pp_console_blob(pp, decode_path_len_decrease=0):
    cols = [" " * len("XXXXXYYZZ [X,X,XXXX]Z")]
    decode_path_len = len(pp.decode_path) - decode_path_len_decrease
    if decode_path_len > 0:
        cols.append(" ." * (decode_path_len + 1))
    if pp.blob.__class__ == bytes:
        blob = hexenc(pp.blob).upper()
        for i in range(0, len(blob), 32):
            chunk = blob[i:i + 32]
            yield " ".join(cols + [colonize_hex(chunk)])
    elif pp.blob.__class__ == tuple:
        yield " ".join(cols + [", ".join(pp.blob)])


def pprint(
        obj,
        oid_maps=(),
        big_blobs=False,
        with_colours=False,
        with_decode_path=False,
        decode_path_only=(),
        decode_path=(),
):
    """Pretty print object

    :param Obj obj: object you want to pretty print
    :param oid_maps: list of ``str(OID) <-> human readable string`` dictionaries.
                     Its human readable form is printed when OID is met
    :param big_blobs: if large binary objects are met (like OctetString
                      values), do we need to print them too, on separate
                      lines
    :param with_colours: colourize output, if ``termcolor`` library
                         is available
    :param with_decode_path: print decode path
    :param decode_path_only: print only that specified decode path
    """
    def _pprint_pps(pps):
        for pp in pps:
            if hasattr(pp, "_fields"):
                if (
                        decode_path_only != () and
                        tuple(
                            str(p) for p in pp.decode_path[:len(decode_path_only)]
                        ) != decode_path_only
                ):
                    continue
                if big_blobs:
                    yield pp_console_row(
                        pp,
                        oid_maps=oid_maps,
                        with_offsets=True,
                        with_blob=False,
                        with_colours=with_colours,
                        with_decode_path=with_decode_path,
                        decode_path_len_decrease=len(decode_path_only),
                    )
                    for row in pp_console_blob(
                            pp,
                            decode_path_len_decrease=len(decode_path_only),
                    ):
                        yield row
                else:
                    yield pp_console_row(
                        pp,
                        oid_maps=oid_maps,
                        with_offsets=True,
                        with_blob=True,
                        with_colours=with_colours,
                        with_decode_path=with_decode_path,
                        decode_path_len_decrease=len(decode_path_only),
                    )
            else:
                for row in _pprint_pps(pp):
                    yield row
    return "\n".join(_pprint_pps(obj.pps(decode_path)))


########################################################################
# ASN.1 primitive types
########################################################################

BooleanState = namedtuple(
    "BooleanState",
    BasicState._fields + ("value",),
    **NAMEDTUPLE_KWARGS
)


class Boolean(Obj):
    """``BOOLEAN`` boolean type

    >>> b = Boolean(True)
    BOOLEAN True
    >>> b == Boolean(True)
    True
    >>> bool(b)
    True
    """
    __slots__ = ()
    tag_default = tag_encode(1)
    asn1_type_name = "BOOLEAN"

    def __init__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either boolean type, or
                      :py:class:`pyderasn.Boolean` object
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, default, optional, _decoded)
        self._value = None if value is None else self._value_sanitize(value)
        if default is not None:
            default = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
            )
            if value is None:
                self._value = default

    def _value_sanitize(self, value):
        if value.__class__ == bool:
            return value
        if issubclass(value.__class__, Boolean):
            return value._value
        raise InvalidValueType((self.__class__, bool))

    @property
    def ready(self):
        return self._value is not None

    def __getstate__(self):
        return BooleanState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self._value,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self._value = state.value

    def __nonzero__(self):
        self._assert_ready()
        return self._value

    def __bool__(self):
        self._assert_ready()
        return self._value

    def __eq__(self, their):
        if their.__class__ == bool:
            return self._value == their
        if not issubclass(their.__class__, Boolean):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    def __call__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    def _encode(self):
        self._assert_ready()
        return b"".join((self.tag, LEN1, (b"\xFF" if self._value else b"\x00")))

    def _encode1st(self, state):
        return len(self.tag) + 2, state

    def _encode2nd(self, writer, state_iter):
        self._assert_ready()
        write_full(writer, self._encode())

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, _, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:
            yield None
            return
        try:
            l, _, v = len_decode(lv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l != 1:
            raise InvalidLength(
                "Boolean's length must be equal to 1",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        first_octet = v[0]
        ber_encoded = False
        if first_octet == 0:
            value = False
        elif first_octet == 0xFF:
            value = True
        elif ctx.get("bered", False):
            value = True
            ber_encoded = True
        else:
            raise DecodeError(
                "unacceptable Boolean value",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        obj = self.__class__(
            value=value,
            impl=self.tag,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _decoded=(offset, 1, 1),
        )
        obj.ber_encoded = ber_encoded
        yield decode_path, obj, v[1:]

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=str(self._value) if self.ready else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


IntegerState = namedtuple(
    "IntegerState",
    BasicState._fields + ("specs", "value", "bound_min", "bound_max"),
    **NAMEDTUPLE_KWARGS
)


class Integer(Obj):
    """``INTEGER`` integer type

    >>> b = Integer(-123)
    INTEGER -123
    >>> b == Integer(-123)
    True
    >>> int(b)
    -123

    >>> Integer(2, bounds=(1, 3))
    INTEGER 2
    >>> Integer(5, bounds=(1, 3))
    Traceback (most recent call last):
    pyderasn.BoundsError: unsatisfied bounds: 1 <= 5 <= 3

    ::

        class Version(Integer):
            schema = (
                ("v1", 0),
                ("v2", 1),
                ("v3", 2),
            )

    >>> v = Version("v1")
    Version INTEGER v1
    >>> int(v)
    0
    >>> v.named
    'v1'
    >>> v.specs
    {'v3': 2, 'v1': 0, 'v2': 1}
    """
    __slots__ = ("specs", "_bound_min", "_bound_max")
    tag_default = tag_encode(2)
    asn1_type_name = "INTEGER"

    def __init__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _specs=None,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either integer type, named value
                      (if ``schema`` is specified in the class), or
                      :py:class:`pyderasn.Integer` object
        :param bounds: set ``(MIN, MAX)`` value constraint.
                       (-inf, +inf) by default
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, default, optional, _decoded)
        self._value = value
        specs = getattr(self, "schema", {}) if _specs is None else _specs
        self.specs = specs if specs.__class__ == dict else dict(specs)
        self._bound_min, self._bound_max = getattr(
            self,
            "bounds",
            (float("-inf"), float("+inf")),
        ) if bounds is None else bounds
        if value is not None:
            self._value = self._value_sanitize(value)
        if default is not None:
            default = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
                _specs=self.specs,
            )
            if self._value is None:
                self._value = default

    def _value_sanitize(self, value):
        if isinstance(value, int):
            pass
        elif issubclass(value.__class__, Integer):
            value = value._value
        elif value.__class__ == str:
            value = self.specs.get(value)
            if value is None:
                raise ObjUnknown("integer value: %s" % value)
        else:
            raise InvalidValueType((self.__class__, int, str))
        if not self._bound_min <= value <= self._bound_max:
            raise BoundsError(self._bound_min, value, self._bound_max)
        return value

    @property
    def ready(self):
        return self._value is not None

    def __getstate__(self):
        return IntegerState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self.specs,
            self._value,
            self._bound_min,
            self._bound_max,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self.specs = state.specs
        self._value = state.value
        self._bound_min = state.bound_min
        self._bound_max = state.bound_max

    def __int__(self):
        self._assert_ready()
        return int(self._value)

    def tohex(self):
        """Hexadecimal representation

        Use :py:func:`pyderasn.colonize_hex` for colonizing it.
        """
        hex_repr = hex(int(self))[2:].upper()
        if len(hex_repr) % 2 != 0:
            hex_repr = "0" + hex_repr
        return hex_repr

    def __hash__(self):
        self._assert_ready()
        return hash(b"".join((
            self.tag,
            bytes(self._expl or b""),
            str(self._value).encode("ascii"),
        )))

    def __eq__(self, their):
        if isinstance(their, int):
            return self._value == their
        if not issubclass(their.__class__, Integer):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    def __lt__(self, their):
        return self._value < their._value

    @property
    def named(self):
        """Return named representation (if exists) of the value
        """
        for name, value in self.specs.items():
            if value == self._value:
                return name
        return None

    def __call__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            bounds=(
                (self._bound_min, self._bound_max)
                if bounds is None else bounds
            ),
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
            _specs=self.specs,
        )

    def _encode_payload(self):
        self._assert_ready()
        value = self._value
        bytes_len = ceil(value.bit_length() / 8) or 1
        while True:
            try:
                octets = value.to_bytes(bytes_len, byteorder="big", signed=True)
            except OverflowError:
                bytes_len += 1
            else:
                break
        return octets

    def _encode(self):
        octets = self._encode_payload()
        return b"".join((self.tag, len_encode(len(octets)), octets))

    def _encode1st(self, state):
        l = len(self._encode_payload())
        return len(self.tag) + len_size(l) + l, state

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self._encode())

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, _, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:
            yield None
            return
        try:
            l, llen, v = len_decode(lv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l == 0:
            raise NotEnoughData(
                "zero length",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        v, tail = v[:l], v[l:]
        first_octet = v[0]
        if l > 1:
            second_octet = v[1]
            if (
                    ((first_octet == 0x00) and (second_octet & 0x80 == 0)) or
                    ((first_octet == 0xFF) and (second_octet & 0x80 != 0))
            ):
                raise DecodeError(
                    "non normalized integer",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
        value = int.from_bytes(v, byteorder="big", signed=True)
        try:
            obj = self.__class__(
                value=value,
                bounds=(self._bound_min, self._bound_max),
                impl=self.tag,
                expl=self._expl,
                default=self.default,
                optional=self.optional,
                _specs=self.specs,
                _decoded=(offset, llen, l),
            )
        except BoundsError as err:
            raise DecodeError(
                msg=str(err),
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        yield decode_path, obj, tail

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=(self.named or str(self._value)) if self.ready else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


BitStringState = namedtuple(
    "BitStringState",
    BasicState._fields + ("specs", "value", "tag_constructed", "defined"),
    **NAMEDTUPLE_KWARGS
)


class BitString(Obj):
    """``BIT STRING`` bit string type

    >>> BitString(b"hello world")
    BIT STRING 88 bits 68656c6c6f20776f726c64
    >>> bytes(b)
    b'hello world'
    >>> b == b"hello world"
    True
    >>> b.bit_len
    88

    >>> BitString("'0A3B5F291CD'H")
    BIT STRING 44 bits 0a3b5f291cd0
    >>> b = BitString("'010110000000'B")
    BIT STRING 12 bits 5800
    >>> b.bit_len
    12
    >>> b[0], b[1], b[2], b[3]
    (False, True, False, True)
    >>> b[1000]
    False
    >>> [v for v in b]
    [False, True, False, True, True, False, False, False, False, False, False, False]

    ::

        class KeyUsage(BitString):
            schema = (
                ("digitalSignature", 0),
                ("nonRepudiation", 1),
                ("keyEncipherment", 2),
            )

    >>> b = KeyUsage(("keyEncipherment", "nonRepudiation"))
    KeyUsage BIT STRING 3 bits nonRepudiation, keyEncipherment
    >>> b.named
    ['nonRepudiation', 'keyEncipherment']
    >>> b.specs
    {'nonRepudiation': 1, 'digitalSignature': 0, 'keyEncipherment': 2}

    .. note::

       Pay attention that BIT STRING can be encoded both in primitive
       and constructed forms. Decoder always checks constructed form tag
       additionally to specified primitive one. If BER decoding is
       :ref:`not enabled <bered_ctx>`, then decoder will fail, because
       of DER restrictions.
    """
    __slots__ = ("tag_constructed", "specs", "defined")
    tag_default = tag_encode(3)
    asn1_type_name = "BIT STRING"

    def __init__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _specs=None,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either binary type, tuple of named
                      values (if ``schema`` is specified in the class),
                      string in ``'XXX...'B`` form, or
                      :py:class:`pyderasn.BitString` object
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, default, optional, _decoded)
        specs = getattr(self, "schema", {}) if _specs is None else _specs
        self.specs = specs if specs.__class__ == dict else dict(specs)
        self._value = None if value is None else self._value_sanitize(value)
        if default is not None:
            default = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
            )
            if value is None:
                self._value = default
        self.defined = None
        tag_klass, _, tag_num = tag_decode(self.tag)
        self.tag_constructed = tag_encode(
            klass=tag_klass,
            form=TagFormConstructed,
            num=tag_num,
        )

    def _bits2octets(self, bits):
        if len(self.specs) > 0:
            bits = bits.rstrip("0")
        bit_len = len(bits)
        bits += "0" * ((8 - (bit_len % 8)) % 8)
        octets = bytearray(len(bits) // 8)
        for i in range(len(octets)):
            octets[i] = int(bits[i * 8:(i * 8) + 8], 2)
        return bit_len, bytes(octets)

    def _value_sanitize(self, value):
        if isinstance(value, (str, bytes)):
            if (
                    isinstance(value, str) and
                    value.startswith("'")
            ):
                if value.endswith("'B"):
                    value = value[1:-2]
                    if not frozenset(value) <= SET01:
                        raise ValueError("B's coding contains unacceptable chars")
                    return self._bits2octets(value)
                if value.endswith("'H"):
                    value = value[1:-2]
                    return (
                        len(value) * 4,
                        hexdec(value + ("" if len(value) % 2 == 0 else "0")),
                    )
            if value.__class__ == bytes:
                return (len(value) * 8, value)
            raise InvalidValueType((self.__class__, str, bytes))
        if value.__class__ == tuple:
            if (
                    len(value) == 2 and
                    isinstance(value[0], int) and
                    value[1].__class__ == bytes
            ):
                return value
            bits = []
            for name in value:
                bit = self.specs.get(name)
                if bit is None:
                    raise ObjUnknown("BitString value: %s" % name)
                bits.append(bit)
            if len(bits) == 0:
                return self._bits2octets("")
            bits = frozenset(bits)
            return self._bits2octets("".join(
                ("1" if bit in bits else "0")
                for bit in range(max(bits) + 1)
            ))
        if issubclass(value.__class__, BitString):
            return value._value
        raise InvalidValueType((self.__class__, bytes, str))

    @property
    def ready(self):
        return self._value is not None

    def __getstate__(self):
        return BitStringState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self.specs,
            self._value,
            self.tag_constructed,
            self.defined,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self.specs = state.specs
        self._value = state.value
        self.tag_constructed = state.tag_constructed
        self.defined = state.defined

    def __iter__(self):
        self._assert_ready()
        for i in range(self._value[0]):
            yield self[i]

    @property
    def bit_len(self):
        """Returns number of bits in the string
        """
        self._assert_ready()
        return self._value[0]

    def __bytes__(self):
        self._assert_ready()
        return self._value[1]

    def __eq__(self, their):
        if their.__class__ == bytes:
            return self._value[1] == their
        if not issubclass(their.__class__, BitString):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    @property
    def named(self):
        """Named representation (if exists) of the bits

        :returns: [str(name), ...]
        """
        return [name for name, bit in self.specs.items() if self[bit]]

    def __call__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
            _specs=self.specs,
        )

    def __getitem__(self, key):
        if key.__class__ == int:
            bit_len, octets = self._value
            if key >= bit_len:
                return False
            return memoryview(octets)[key // 8] >> (7 - (key % 8)) & 1 == 1
        if isinstance(key, str):
            value = self.specs.get(key)
            if value is None:
                raise ObjUnknown("BitString value: %s" % key)
            return self[value]
        raise InvalidValueType((int, str))

    def _encode(self):
        self._assert_ready()
        bit_len, octets = self._value
        return b"".join((
            self.tag,
            len_encode(len(octets) + 1),
            int2byte((8 - bit_len % 8) % 8),
            octets,
        ))

    def _encode1st(self, state):
        self._assert_ready()
        _, octets = self._value
        l = len(octets) + 1
        return len(self.tag) + len_size(l) + l, state

    def _encode2nd(self, writer, state_iter):
        bit_len, octets = self._value
        write_full(writer, b"".join((
            self.tag,
            len_encode(len(octets) + 1),
            int2byte((8 - bit_len % 8) % 8),
        )))
        write_full(writer, octets)

    def _encode_cer(self, writer):
        bit_len, octets = self._value
        if len(octets) + 1 <= 1000:
            write_full(writer, self._encode())
            return
        write_full(writer, self.tag_constructed)
        write_full(writer, LENINDEF)
        for offset in range(0, (len(octets) // 999) * 999, 999):
            write_full(writer, b"".join((
                BitString.tag_default,
                LEN1K,
                b"\x00",
                octets[offset:offset + 999],
            )))
        tail = octets[offset + 999:]
        if len(tail) > 0:
            tail = int2byte((8 - bit_len % 8) % 8) + tail
            write_full(writer, b"".join((
                BitString.tag_default,
                len_encode(len(tail)),
                tail,
            )))
        write_full(writer, EOC)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t == self.tag:
            if tag_only:  # pragma: no cover
                yield None
                return
            try:
                l, llen, v = len_decode(lv)
            except DecodeError as err:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if l > len(v):
                raise NotEnoughData(
                    "encoded length is longer than data",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if l == 0:
                raise NotEnoughData(
                    "zero length",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            pad_size = v[0]
            if l == 1 and pad_size != 0:
                raise DecodeError(
                    "invalid empty value",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if pad_size > 7:
                raise DecodeError(
                    "too big pad",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if v[l - 1] & ((1 << pad_size) - 1) != 0:
                raise DecodeError(
                    "invalid pad",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            v, tail = v[:l], v[l:]
            bit_len = (len(v) - 1) * 8 - pad_size
            obj = self.__class__(
                value=None if evgen_mode else (bit_len, v[1:].tobytes()),
                impl=self.tag,
                expl=self._expl,
                default=self.default,
                optional=self.optional,
                _specs=self.specs,
                _decoded=(offset, llen, l),
            )
            if evgen_mode:
                obj._value = (bit_len, None)
            yield decode_path, obj, tail
            return
        if t != self.tag_constructed:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if not ctx.get("bered", False):
            raise DecodeError(
                "unallowed BER constructed encoding",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:  # pragma: no cover
            yield None
            return
        lenindef = False
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm:
            llen, l, v = 1, 0, lv[1:]
            lenindef = True
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if not lenindef and l == 0:
            raise NotEnoughData(
                "zero length",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        chunks = []
        sub_offset = offset + tlen + llen
        vlen = 0
        while True:
            if lenindef:
                if v[:EOC_LEN].tobytes() == EOC:
                    break
            else:
                if vlen == l:
                    break
                if vlen > l:
                    raise DecodeError(
                        "chunk out of bounds",
                        klass=self.__class__,
                        decode_path=decode_path + (str(len(chunks) - 1),),
                        offset=chunks[-1].offset,
                    )
            sub_decode_path = decode_path + (str(len(chunks)),)
            try:
                if evgen_mode:
                    for _decode_path, chunk, v_tail in BitString().decode_evgen(
                            v,
                            offset=sub_offset,
                            decode_path=sub_decode_path,
                            leavemm=True,
                            ctx=ctx,
                            _ctx_immutable=False,
                    ):
                        yield _decode_path, chunk, v_tail
                else:
                    _, chunk, v_tail = next(BitString().decode_evgen(
                        v,
                        offset=sub_offset,
                        decode_path=sub_decode_path,
                        leavemm=True,
                        ctx=ctx,
                        _ctx_immutable=False,
                        _evgen_mode=False,
                    ))
            except TagMismatch:
                raise DecodeError(
                    "expected BitString encoded chunk",
                    klass=self.__class__,
                    decode_path=sub_decode_path,
                    offset=sub_offset,
                )
            chunks.append(chunk)
            sub_offset += chunk.tlvlen
            vlen += chunk.tlvlen
            v = v_tail
        if len(chunks) == 0:
            raise DecodeError(
                "no chunks",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        values = []
        bit_len = 0
        for chunk_i, chunk in enumerate(chunks[:-1]):
            if chunk.bit_len % 8 != 0:
                raise DecodeError(
                    "BitString chunk is not multiple of 8 bits",
                    klass=self.__class__,
                    decode_path=decode_path + (str(chunk_i),),
                    offset=chunk.offset,
                )
            if not evgen_mode:
                values.append(bytes(chunk))
            bit_len += chunk.bit_len
        chunk_last = chunks[-1]
        if not evgen_mode:
            values.append(bytes(chunk_last))
        bit_len += chunk_last.bit_len
        obj = self.__class__(
            value=None if evgen_mode else (bit_len, b"".join(values)),
            impl=self.tag,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _specs=self.specs,
            _decoded=(offset, llen, vlen + (EOC_LEN if lenindef else 0)),
        )
        if evgen_mode:
            obj._value = (bit_len, None)
        obj.lenindef = lenindef
        obj.ber_encoded = True
        yield decode_path, obj, (v[EOC_LEN:] if lenindef else v)

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        value = None
        blob = None
        if self.ready:
            bit_len, blob = self._value
            value = "%d bits" % bit_len
            if len(self.specs) > 0 and blob is not None:
                blob = tuple(self.named)
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=value,
            blob=blob,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            lenindef=self.lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        defined_by, defined = self.defined or (None, None)
        if defined_by is not None:
            yield defined.pps(
                decode_path=decode_path + (DecodePathDefBy(defined_by),)
            )
        for pp in self.pps_lenindef(decode_path):
            yield pp


OctetStringState = namedtuple(
    "OctetStringState",
    BasicState._fields + (
        "value",
        "bound_min",
        "bound_max",
        "tag_constructed",
        "defined",
    ),
    **NAMEDTUPLE_KWARGS
)


class OctetString(Obj):
    """``OCTET STRING`` binary string type

    >>> s = OctetString(b"hello world")
    OCTET STRING 11 bytes 68656c6c6f20776f726c64
    >>> s == OctetString(b"hello world")
    True
    >>> bytes(s)
    b'hello world'

    >>> OctetString(b"hello", bounds=(4, 4))
    Traceback (most recent call last):
    pyderasn.BoundsError: unsatisfied bounds: 4 <= 5 <= 4
    >>> OctetString(b"hell", bounds=(4, 4))
    OCTET STRING 4 bytes 68656c6c

    Memoryviews can be used as a values. If memoryview is made on
    mmap-ed file, then it does not take storage inside OctetString
    itself. In CER encoding mode it will be streamed to the specified
    writer, copying 1 KB chunks.
    """
    __slots__ = ("tag_constructed", "_bound_min", "_bound_max", "defined")
    tag_default = tag_encode(4)
    asn1_type_name = "OCTET STRING"
    evgen_mode_skip_value = True
    memoryview_safe = True

    def __init__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
            ctx=None,
    ):
        """
        :param value: set the value. Either binary type, or
                      :py:class:`pyderasn.OctetString` object
        :param bounds: set ``(MIN, MAX)`` value size constraint.
                       (-inf, +inf) by default
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, default, optional, _decoded)
        self._value = value
        self._bound_min, self._bound_max = getattr(
            self,
            "bounds",
            (0, float("+inf")),
        ) if bounds is None else bounds
        if value is not None:
            self._value = self._value_sanitize(value)
        if default is not None:
            default = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
            )
            if self._value is None:
                self._value = default
        self.defined = None
        tag_klass, _, tag_num = tag_decode(self.tag)
        self.tag_constructed = tag_encode(
            klass=tag_klass,
            form=TagFormConstructed,
            num=tag_num,
        )

    def _value_sanitize(self, value):
        if value.__class__ == bytes or value.__class__ == memoryview:
            pass
        elif issubclass(value.__class__, OctetString):
            value = value._value
        else:
            raise InvalidValueType((self.__class__, bytes, memoryview))
        if not self._bound_min <= len(value) <= self._bound_max:
            raise BoundsError(self._bound_min, len(value), self._bound_max)
        return value

    @property
    def ready(self):
        return self._value is not None

    def __getstate__(self):
        return OctetStringState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self._value,
            self._bound_min,
            self._bound_max,
            self.tag_constructed,
            self.defined,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self._value = state.value
        self._bound_min = state.bound_min
        self._bound_max = state.bound_max
        self.tag_constructed = state.tag_constructed
        self.defined = state.defined

    def __bytes__(self):
        self._assert_ready()
        return bytes(self._value)

    def memoryview(self):
        self._assert_ready()
        return memoryview(self._value)

    def __eq__(self, their):
        if their.__class__ == bytes:
            return self._value == their
        if not issubclass(their.__class__, OctetString):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    def __lt__(self, their):
        return self._value < their._value

    def __call__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            bounds=(
                (self._bound_min, self._bound_max)
                if bounds is None else bounds
            ),
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    def _encode(self):
        self._assert_ready()
        return b"".join((
            self.tag,
            len_encode(len(self._value)),
            self._value,
        ))

    def _encode1st(self, state):
        self._assert_ready()
        l = len(self._value)
        return len(self.tag) + len_size(l) + l, state

    def _encode2nd(self, writer, state_iter):
        value = self._value
        write_full(writer, self.tag + len_encode(len(value)))
        write_full(writer, value)

    def _encode_cer(self, writer):
        octets = self._value
        if len(octets) <= 1000:
            write_full(writer, self._encode())
            return
        write_full(writer, self.tag_constructed)
        write_full(writer, LENINDEF)
        for offset in range(0, (len(octets) // 1000) * 1000, 1000):
            write_full(writer, b"".join((
                OctetString.tag_default,
                LEN1K,
                octets[offset:offset + 1000],
            )))
        tail = octets[offset + 1000:]
        if len(tail) > 0:
            write_full(writer, b"".join((
                OctetString.tag_default,
                len_encode(len(tail)),
                tail,
            )))
        write_full(writer, EOC)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t == self.tag:
            if tag_only:
                yield None
                return
            try:
                l, llen, v = len_decode(lv)
            except DecodeError as err:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if l > len(v):
                raise NotEnoughData(
                    "encoded length is longer than data",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            v, tail = v[:l], v[l:]
            if evgen_mode and not self._bound_min <= len(v) <= self._bound_max:
                raise DecodeError(
                    msg=str(BoundsError(self._bound_min, len(v), self._bound_max)),
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            if evgen_mode and self.evgen_mode_skip_value:
                value = None
            elif self.memoryview_safe and ctx.get("keep_memoryview", False):
                value = v
            else:
                value = v.tobytes()
            try:
                obj = self.__class__(
                    value=value,
                    bounds=(self._bound_min, self._bound_max),
                    impl=self.tag,
                    expl=self._expl,
                    default=self.default,
                    optional=self.optional,
                    _decoded=(offset, llen, l),
                    ctx=ctx,
                )
            except DecodeError as err:
                raise DecodeError(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            except BoundsError as err:
                raise DecodeError(
                    msg=str(err),
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            yield decode_path, obj, tail
            return
        if t != self.tag_constructed:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if not ctx.get("bered", False):
            raise DecodeError(
                "unallowed BER constructed encoding",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:
            yield None
            return
        lenindef = False
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm:
            llen, l, v = 1, 0, lv[1:]
            lenindef = True
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        chunks = []
        chunks_count = 0
        sub_offset = offset + tlen + llen
        vlen = 0
        payload_len = 0
        while True:
            if lenindef:
                if v[:EOC_LEN].tobytes() == EOC:
                    break
            else:
                if vlen == l:
                    break
                if vlen > l:
                    raise DecodeError(
                        "chunk out of bounds",
                        klass=self.__class__,
                        decode_path=decode_path + (str(len(chunks) - 1),),
                        offset=chunks[-1].offset,
                    )
            try:
                if evgen_mode:
                    sub_decode_path = decode_path + (str(chunks_count),)
                    for _decode_path, chunk, v_tail in OctetString().decode_evgen(
                            v,
                            offset=sub_offset,
                            decode_path=sub_decode_path,
                            leavemm=True,
                            ctx=ctx,
                            _ctx_immutable=False,
                    ):
                        yield _decode_path, chunk, v_tail
                        if not chunk.ber_encoded:
                            payload_len += chunk.vlen
                    chunks_count += 1
                else:
                    sub_decode_path = decode_path + (str(len(chunks)),)
                    _, chunk, v_tail = next(OctetString().decode_evgen(
                        v,
                        offset=sub_offset,
                        decode_path=sub_decode_path,
                        leavemm=True,
                        ctx=ctx,
                        _ctx_immutable=False,
                        _evgen_mode=False,
                    ))
                    chunks.append(chunk)
            except TagMismatch:
                raise DecodeError(
                    "expected OctetString encoded chunk",
                    klass=self.__class__,
                    decode_path=sub_decode_path,
                    offset=sub_offset,
                )
            sub_offset += chunk.tlvlen
            vlen += chunk.tlvlen
            v = v_tail
        if evgen_mode and not self._bound_min <= payload_len <= self._bound_max:
            raise DecodeError(
                msg=str(BoundsError(self._bound_min, payload_len, self._bound_max)),
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        try:
            obj = self.__class__(
                value=(
                    None if evgen_mode else
                    b"".join(bytes(chunk) for chunk in chunks)
                ),
                bounds=(self._bound_min, self._bound_max),
                impl=self.tag,
                expl=self._expl,
                default=self.default,
                optional=self.optional,
                _decoded=(offset, llen, vlen + (EOC_LEN if lenindef else 0)),
                ctx=ctx,
            )
        except DecodeError as err:
            raise DecodeError(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        except BoundsError as err:
            raise DecodeError(
                msg=str(err),
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        obj.lenindef = lenindef
        obj.ber_encoded = True
        yield decode_path, obj, (v[EOC_LEN:] if lenindef else v)

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=("%d bytes" % len(self._value)) if self.ready else None,
            blob=self._value if self.ready else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            lenindef=self.lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        defined_by, defined = self.defined or (None, None)
        if defined_by is not None:
            yield defined.pps(
                decode_path=decode_path + (DecodePathDefBy(defined_by),)
            )
        for pp in self.pps_lenindef(decode_path):
            yield pp


def agg_octet_string(evgens, decode_path, raw, writer):
    """Aggregate constructed string (OctetString and its derivatives)

    :param evgens: iterator of generated events
    :param decode_path: points to the string we want to decode
    :param raw: slicebable (memoryview, bytearray, etc) with
                the data evgens are generated on
    :param writer: buffer.write where string is going to be saved
    :param writer: where string is going to be saved. Must comply
                   with ``io.RawIOBase.write`` behaviour

    .. seealso:: :ref:`agg_octet_string`
    """
    decode_path_len = len(decode_path)
    for dp, obj, _ in evgens:
        if dp[:decode_path_len] != decode_path:
            continue
        if not obj.ber_encoded:
            write_full(writer, raw[
                obj.offset + obj.tlen + obj.llen:
                obj.offset + obj.tlen + obj.llen + obj.vlen -
                (EOC_LEN if obj.expl_lenindef else 0)
            ])
        if len(dp) == decode_path_len:
            break


NullState = namedtuple("NullState", BasicState._fields, **NAMEDTUPLE_KWARGS)


class Null(Obj):
    """``NULL`` null object

    >>> n = Null()
    NULL
    >>> n.ready
    True
    """
    __slots__ = ()
    tag_default = tag_encode(5)
    asn1_type_name = "NULL"

    def __init__(
            self,
            value=None,  # unused, but Sequence passes it
            impl=None,
            expl=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        """
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, None, optional, _decoded)
        self.default = None

    @property
    def ready(self):
        return True

    def __getstate__(self):
        return NullState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
        )

    def __eq__(self, their):
        if not issubclass(their.__class__, Null):
            return False
        return (
            self.tag == their.tag and
            self._expl == their._expl
        )

    def __call__(
            self,
            value=None,
            impl=None,
            expl=None,
            optional=None,
    ):
        return self.__class__(
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            optional=self.optional if optional is None else optional,
        )

    def _encode(self):
        return self.tag + LEN0

    def _encode1st(self, state):
        return len(self.tag) + 1, state

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self.tag + LEN0)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, _, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:  # pragma: no cover
            yield None
            return
        try:
            l, _, v = len_decode(lv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l != 0:
            raise InvalidLength(
                "Null must have zero length",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        obj = self.__class__(
            impl=self.tag,
            expl=self._expl,
            optional=self.optional,
            _decoded=(offset, 1, 0),
        )
        yield decode_path, obj, v

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            optional=self.optional,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


ObjectIdentifierState = namedtuple(
    "ObjectIdentifierState",
    BasicState._fields + ("value", "defines"),
    **NAMEDTUPLE_KWARGS
)


class ObjectIdentifier(Obj):
    """``OBJECT IDENTIFIER`` OID type

    >>> oid = ObjectIdentifier((1, 2, 3))
    OBJECT IDENTIFIER 1.2.3
    >>> oid == ObjectIdentifier("1.2.3")
    True
    >>> tuple(oid)
    (1, 2, 3)
    >>> str(oid)
    '1.2.3'
    >>> oid + (4, 5) + ObjectIdentifier("1.7")
    OBJECT IDENTIFIER 1.2.3.4.5.1.7

    >>> str(ObjectIdentifier((3, 1)))
    Traceback (most recent call last):
    pyderasn.InvalidOID: unacceptable first arc value
    """
    __slots__ = ("defines",)
    tag_default = tag_encode(6)
    asn1_type_name = "OBJECT IDENTIFIER"

    def __init__(
            self,
            value=None,
            defines=(),
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either tuples of integers,
                      string of "."-concatenated integers, or
                      :py:class:`pyderasn.ObjectIdentifier` object
        :param defines: sequence of tuples. Each tuple has two elements.
                        First one is relative to current one decode
                        path, aiming to the field defined by that OID.
                        Read about relative path in
                        :py:func:`pyderasn.abs_decode_path`. Second
                        tuple element is ``{OID: pyderasn.Obj()}``
                        dictionary, mapping between current OID value
                        and structure applied to defined field.

                        .. seealso:: :ref:`definedby`

        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(impl, expl, default, optional, _decoded)
        self._value = value
        if value is not None:
            self._value = self._value_sanitize(value)
        if default is not None:
            default = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
            )
            if self._value is None:
                self._value = default
        self.defines = defines

    def __add__(self, their):
        if their.__class__ == tuple:
            return self.__class__(self._value + array("L", their))
        if isinstance(their, self.__class__):
            return self.__class__(self._value + their._value)
        raise InvalidValueType((self.__class__, tuple))

    def _value_sanitize(self, value):
        if issubclass(value.__class__, ObjectIdentifier):
            return value._value
        if isinstance(value, str):
            try:
                value = array("L", (pureint(arc) for arc in value.split(".")))
            except ValueError:
                raise InvalidOID("unacceptable arcs values")
        if value.__class__ == tuple:
            try:
                value = array("L", value)
            except OverflowError as err:
                raise InvalidOID(repr(err))
        if value.__class__ is array:
            if len(value) < 2:
                raise InvalidOID("less than 2 arcs")
            first_arc = value[0]
            if first_arc in (0, 1):
                if not (0 <= value[1] <= 39):
                    raise InvalidOID("second arc is too wide")
            elif first_arc == 2:
                pass
            else:
                raise InvalidOID("unacceptable first arc value")
            if not all(arc >= 0 for arc in value):
                raise InvalidOID("negative arc value")
            return value
        raise InvalidValueType((self.__class__, str, tuple))

    @property
    def ready(self):
        return self._value is not None

    def __getstate__(self):
        return ObjectIdentifierState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self._value,
            self.defines,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self._value = state.value
        self.defines = state.defines

    def __iter__(self):
        self._assert_ready()
        return iter(self._value)

    def __str__(self):
        return ".".join(str(arc) for arc in self._value or ())

    def __hash__(self):
        self._assert_ready()
        return hash(b"".join((
            self.tag,
            bytes(self._expl or b""),
            str(self._value).encode("ascii"),
        )))

    def __eq__(self, their):
        if their.__class__ == tuple:
            return self._value == array("L", their)
        if not issubclass(their.__class__, ObjectIdentifier):
            return False
        return (
            self.tag == their.tag and
            self._expl == their._expl and
            self._value == their._value
        )

    def __lt__(self, their):
        return self._value < their._value

    def __call__(
            self,
            value=None,
            defines=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            defines=self.defines if defines is None else defines,
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    def _encode_octets(self):
        self._assert_ready()
        value = self._value
        first_value = value[1]
        first_arc = value[0]
        if first_arc == 0:
            pass
        elif first_arc == 1:
            first_value += 40
        elif first_arc == 2:
            first_value += 80
        else:  # pragma: no cover
            raise RuntimeError("invalid arc is stored")
        octets = [zero_ended_encode(first_value)]
        for arc in value[2:]:
            octets.append(zero_ended_encode(arc))
        return b"".join(octets)

    def _encode(self):
        v = self._encode_octets()
        return b"".join((self.tag, len_encode(len(v)), v))

    def _encode1st(self, state):
        l = len(self._encode_octets())
        return len(self.tag) + len_size(l) + l, state

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self._encode())

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, _, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:  # pragma: no cover
            yield None
            return
        try:
            l, llen, v = len_decode(lv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l == 0:
            raise NotEnoughData(
                "zero length",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        v, tail = v[:l], v[l:]
        arcs = array("L")
        ber_encoded = False
        while len(v) > 0:
            i = 0
            arc = 0
            while True:
                octet = v[i]
                if i == 0 and octet == 0x80:
                    if ctx.get("bered", False):
                        ber_encoded = True
                    else:
                        raise DecodeError(
                            "non normalized arc encoding",
                            klass=self.__class__,
                            decode_path=decode_path,
                            offset=offset,
                        )
                arc = (arc << 7) | (octet & 0x7F)
                if octet & 0x80 == 0:
                    try:
                        arcs.append(arc)
                    except OverflowError:
                        raise DecodeError(
                            "too huge value for local unsigned long",
                            klass=self.__class__,
                            decode_path=decode_path,
                            offset=offset,
                        )
                    v = v[i + 1:]
                    break
                i += 1
                if i == len(v):
                    raise DecodeError(
                        "unfinished OID",
                        klass=self.__class__,
                        decode_path=decode_path,
                        offset=offset,
                    )
        first_arc = 0
        second_arc = arcs[0]
        if 0 <= second_arc <= 39:
            first_arc = 0
        elif 40 <= second_arc <= 79:
            first_arc = 1
            second_arc -= 40
        else:
            first_arc = 2
            second_arc -= 80
        obj = self.__class__(
            value=array("L", (first_arc, second_arc)) + arcs[1:],
            impl=self.tag,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _decoded=(offset, llen, l),
        )
        if ber_encoded:
            obj.ber_encoded = True
        yield decode_path, obj, tail

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=str(self) if self.ready else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


class Enumerated(Integer):
    """``ENUMERATED`` integer type

    This type is identical to :py:class:`pyderasn.Integer`, but requires
    schema to be specified and does not accept values missing from it.
    """
    __slots__ = ()
    tag_default = tag_encode(10)
    asn1_type_name = "ENUMERATED"

    def __init__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _specs=None,
            _decoded=(0, 0, 0),
            bounds=None,  # dummy argument, workability for Integer.decode
    ):
        super().__init__(
            value, bounds, impl, expl, default, optional, _specs, _decoded,
        )
        if len(self.specs) == 0:
            raise ValueError("schema must be specified")

    def _value_sanitize(self, value):
        if isinstance(value, self.__class__):
            value = value._value
        elif isinstance(value, int):
            for _value in self.specs.values():
                if _value == value:
                    break
            else:
                raise DecodeError(
                    "unknown integer value: %s" % value,
                    klass=self.__class__,
                )
        elif isinstance(value, str):
            value = self.specs.get(value)
            if value is None:
                raise ObjUnknown("integer value: %s" % value)
        else:
            raise InvalidValueType((self.__class__, int, str))
        return value

    def __call__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
            _specs=None,
    ):
        return self.__class__(
            value=value,
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
            _specs=self.specs,
        )


def escape_control_unicode(c):
    if unicat(c)[0] == "C":
        c = repr(c).lstrip("u").strip("'")
    return c


class CommonString(OctetString):
    """Common class for all strings

    Everything resembles :py:class:`pyderasn.OctetString`, except
    ability to deal with unicode text strings.

    >>> hexenc("привет мир".encode("utf-8"))
    'd0bfd180d0b8d0b2d0b5d18220d0bcd0b8d180'
    >>> UTF8String("привет мир") == UTF8String(hexdec("d0...80"))
    True
    >>> s = UTF8String("привет мир")
    UTF8String UTF8String привет мир
    >>> str(s)
    'привет мир'
    >>> hexenc(bytes(s))
    'd0bfd180d0b8d0b2d0b5d18220d0bcd0b8d180'

    >>> PrintableString("привет мир")
    Traceback (most recent call last):
    pyderasn.DecodeError: 'ascii' codec can't encode characters in position 0-5: ordinal not in range(128)

    >>> BMPString("ада", bounds=(2, 2))
    Traceback (most recent call last):
    pyderasn.BoundsError: unsatisfied bounds: 2 <= 3 <= 2
    >>> s = BMPString("ад", bounds=(2, 2))
    >>> s.encoding
    'utf-16-be'
    >>> hexenc(bytes(s))
    '04300434'

    .. list-table::
       :header-rows: 1

       * - Class
         - Text Encoding, validation
       * - :py:class:`pyderasn.UTF8String`
         - utf-8
       * - :py:class:`pyderasn.NumericString`
         - proper alphabet validation
       * - :py:class:`pyderasn.PrintableString`
         - proper alphabet validation
       * - :py:class:`pyderasn.TeletexString`
         - iso-8859-1
       * - :py:class:`pyderasn.T61String`
         - iso-8859-1
       * - :py:class:`pyderasn.VideotexString`
         - iso-8859-1
       * - :py:class:`pyderasn.IA5String`
         - proper alphabet validation
       * - :py:class:`pyderasn.GraphicString`
         - iso-8859-1
       * - :py:class:`pyderasn.VisibleString`, :py:class:`pyderasn.ISO646String`
         - proper alphabet validation
       * - :py:class:`pyderasn.GeneralString`
         - iso-8859-1
       * - :py:class:`pyderasn.UniversalString`
         - utf-32-be
       * - :py:class:`pyderasn.BMPString`
         - utf-16-be
    """
    __slots__ = ()
    memoryview_safe = False

    def _value_sanitize(self, value):
        value_raw = None
        value_decoded = None
        if isinstance(value, self.__class__):
            value_raw = value._value
        elif value.__class__ == str:
            value_decoded = value
        elif value.__class__ == bytes:
            value_raw = value
        else:
            raise InvalidValueType((self.__class__, str, bytes))
        try:
            value_raw = (
                value_decoded.encode(self.encoding)
                if value_raw is None else value_raw
            )
            value_decoded = (
                value_raw.decode(self.encoding)
                if value_decoded is None else value_decoded
            )
        except (UnicodeEncodeError, UnicodeDecodeError) as err:
            raise DecodeError(str(err))
        if not self._bound_min <= len(value_decoded) <= self._bound_max:
            raise BoundsError(
                self._bound_min,
                len(value_decoded),
                self._bound_max,
            )
        return value_raw

    def __eq__(self, their):
        if their.__class__ == bytes:
            return self._value == their
        if their.__class__ == str:
            return self._value == their.encode(self.encoding)
        if not isinstance(their, self.__class__):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    def __unicode__(self):
        if self.ready:
            return self._value.decode(self.encoding)
        return str(self._value)

    def memoryview(self):
        raise ValueError("CommonString does not support .memoryview()")

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        value = None
        if self.ready:
            value = "".join(escape_control_unicode(c) for c in self.__unicode__())
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=value,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


class UTF8String(CommonString):
    __slots__ = ()
    tag_default = tag_encode(12)
    encoding = "utf-8"
    asn1_type_name = "UTF8String"


class AllowableCharsMixin:
    __slots__ = ()

    @property
    def allowable_chars(self):
        return frozenset(chr(c) for c in self._allowable_chars)

    def _value_sanitize(self, value):
        value = super()._value_sanitize(value)
        if not frozenset(value) <= self._allowable_chars:
            raise DecodeError("non satisfying alphabet value")
        return value


NUMERIC_ALLOWABLE_CHARS = frozenset(digits.encode("ascii") + b" ")


class NumericString(AllowableCharsMixin, CommonString):
    """Numeric string

    Its value is properly sanitized: only ASCII digits with spaces can
    be stored.

    >>> NumericString().allowable_chars
    frozenset(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' '])
    """
    __slots__ = ("_allowable_chars",)
    tag_default = tag_encode(18)
    encoding = "ascii"
    asn1_type_name = "NumericString"

    def __init__(self, *args, **kwargs):
        self._allowable_chars = NUMERIC_ALLOWABLE_CHARS
        super().__init__(*args, **kwargs)


PrintableStringState = namedtuple(
    "PrintableStringState",
    OctetStringState._fields + ("allowable_chars",),
    **NAMEDTUPLE_KWARGS
)


PRINTABLE_ALLOWABLE_CHARS = frozenset(
    (ascii_letters + digits + " '()+,-./:=?").encode("ascii")
)


class PrintableString(AllowableCharsMixin, CommonString):
    """Printable string

    Its value is properly sanitized: see X.680 41.4 table 10.

    >>> PrintableString().allowable_chars
    frozenset([' ', "'", ..., 'z'])
    >>> obj = PrintableString("foo*bar", allow_asterisk=True)
    PrintableString PrintableString foo*bar
    >>> obj.allow_asterisk, obj.allow_ampersand
    (True, False)
    """
    __slots__ = ("_allowable_chars",)
    tag_default = tag_encode(19)
    encoding = "ascii"
    asn1_type_name = "PrintableString"
    _asterisk = frozenset("*".encode("ascii"))
    _ampersand = frozenset("&".encode("ascii"))

    def __init__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
            ctx=None,
            allow_asterisk=False,
            allow_ampersand=False,
    ):
        """
        :param allow_asterisk: allow asterisk character
        :param allow_ampersand: allow ampersand character
        """
        allowable_chars = PRINTABLE_ALLOWABLE_CHARS
        if allow_asterisk:
            allowable_chars |= self._asterisk
        if allow_ampersand:
            allowable_chars |= self._ampersand
        self._allowable_chars = allowable_chars
        super().__init__(
            value, bounds, impl, expl, default, optional, _decoded, ctx,
        )

    @property
    def allow_asterisk(self):
        """Is asterisk character allowed?
        """
        return self._asterisk <= self._allowable_chars

    @property
    def allow_ampersand(self):
        """Is ampersand character allowed?
        """
        return self._ampersand <= self._allowable_chars

    def __getstate__(self):
        return PrintableStringState(
            *super().__getstate__(),
            **{"allowable_chars": self._allowable_chars}
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self._allowable_chars = state.allowable_chars

    def __call__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            bounds=(
                (self._bound_min, self._bound_max)
                if bounds is None else bounds
            ),
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
            allow_asterisk=self.allow_asterisk,
            allow_ampersand=self.allow_ampersand,
        )


class TeletexString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(20)
    encoding = "iso-8859-1"
    asn1_type_name = "TeletexString"


class T61String(TeletexString):
    __slots__ = ()
    asn1_type_name = "T61String"


class VideotexString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(21)
    encoding = "iso-8859-1"
    asn1_type_name = "VideotexString"


IA5_ALLOWABLE_CHARS = frozenset(b"".join(
    chr(c).encode("ascii") for c in range(128)
))


class IA5String(AllowableCharsMixin, CommonString):
    """IA5 string

    Its value is properly sanitized: it is a mix of

    * http://www.itscj.ipsj.or.jp/iso-ir/006.pdf (G)
    * http://www.itscj.ipsj.or.jp/iso-ir/001.pdf (C0)
    * DEL character (0x7F)

    It is just 7-bit ASCII.

    >>> IA5String().allowable_chars
    frozenset(["NUL", ... "DEL"])
    """
    __slots__ = ("_allowable_chars",)
    tag_default = tag_encode(22)
    encoding = "ascii"
    asn1_type_name = "IA5"

    def __init__(self, *args, **kwargs):
        self._allowable_chars = IA5_ALLOWABLE_CHARS
        super().__init__(*args, **kwargs)


LEN_YYMMDDHHMMSSZ = len("YYMMDDHHMMSSZ")
LEN_LEN_YYMMDDHHMMSSZ = len_encode(LEN_YYMMDDHHMMSSZ)
LEN_YYMMDDHHMMSSZ_WITH_LEN = len(LEN_LEN_YYMMDDHHMMSSZ) + LEN_YYMMDDHHMMSSZ
LEN_YYYYMMDDHHMMSSDMZ = len("YYYYMMDDHHMMSSDMZ")
LEN_YYYYMMDDHHMMSSZ = len("YYYYMMDDHHMMSSZ")
LEN_LEN_YYYYMMDDHHMMSSZ = len_encode(LEN_YYYYMMDDHHMMSSZ)


VISIBLE_ALLOWABLE_CHARS = frozenset(b"".join(
    chr(c).encode("ascii") for c in range(ord(" "), ord("~") + 1)
))


class VisibleString(AllowableCharsMixin, CommonString):
    """Visible string

    Its value is properly sanitized. ASCII subset from space to tilde is
    allowed: http://www.itscj.ipsj.or.jp/iso-ir/006.pdf

    >>> VisibleString().allowable_chars
    frozenset([" ", ... "~"])
    """
    __slots__ = ("_allowable_chars",)
    tag_default = tag_encode(26)
    encoding = "ascii"
    asn1_type_name = "VisibleString"

    def __init__(self, *args, **kwargs):
        self._allowable_chars = VISIBLE_ALLOWABLE_CHARS
        super().__init__(*args, **kwargs)


class ISO646String(VisibleString):
    __slots__ = ()
    asn1_type_name = "ISO646String"


UTCTimeState = namedtuple(
    "UTCTimeState",
    OctetStringState._fields + ("ber_raw",),
    **NAMEDTUPLE_KWARGS
)


def str_to_time_fractions(value):
    v = pureint(value)
    year, v = (v // 10**10), (v % 10**10)
    month, v = (v // 10**8), (v % 10**8)
    day, v = (v // 10**6), (v % 10**6)
    hour, v = (v // 10**4), (v % 10**4)
    minute, second = (v // 100), (v % 100)
    return year, month, day, hour, minute, second


class UTCTime(VisibleString):
    """``UTCTime`` datetime type

    >>> t = UTCTime(datetime(2017, 9, 30, 22, 7, 50, 123))
    UTCTime UTCTime 2017-09-30T22:07:50
    >>> str(t)
    '170930220750Z'
    >>> bytes(t)
    b'170930220750Z'
    >>> t.todatetime()
    datetime.datetime(2017, 9, 30, 22, 7, 50)
    >>> UTCTime(datetime(2057, 9, 30, 22, 7, 50)).todatetime()
    datetime.datetime(1957, 9, 30, 22, 7, 50)
    >>> UTCTime(datetime(2057, 9, 30, 22, 7, 50)).totzdatetime()
    datetime.datetime(1957, 9, 30, 22, 7, 50, tzinfo=tzutc())

    If BER encoded value was met, then ``ber_raw`` attribute will hold
    its raw representation.

    .. warning::

       Only **naive** ``datetime`` objects are supported.
       Library assumes that all work is done in UTC.

    .. warning::

       Pay attention that ``UTCTime`` can not hold full year, so all years
       having < 50 years are treated as 20xx, 19xx otherwise, according to
       X.509 recommendation. Use ``GeneralizedTime`` instead for
       removing ambiguity.

    .. warning::

       No strict validation of UTC offsets are made (only applicable to
       **BER**), but very crude:

       * minutes are not exceeding 60
       * offset value is not exceeding 14 hours
    """
    __slots__ = ("ber_raw",)
    tag_default = tag_encode(23)
    encoding = "ascii"
    asn1_type_name = "UTCTime"
    evgen_mode_skip_value = False

    def __init__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
            bounds=None,  # dummy argument, workability for OctetString.decode
            ctx=None,
    ):
        """
        :param value: set the value. Either datetime type, or
                      :py:class:`pyderasn.UTCTime` object
        :param bytes impl: override default tag with ``IMPLICIT`` one
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(None, None, impl, expl, None, optional, _decoded, ctx)
        self._value = value
        self.ber_raw = None
        if value is not None:
            self._value, self.ber_raw = self._value_sanitize(value, ctx)
            self.ber_encoded = self.ber_raw is not None
        if default is not None:
            default, _ = self._value_sanitize(default)
            self.default = self.__class__(
                value=default,
                impl=self.tag,
                expl=self._expl,
            )
            if self._value is None:
                self._value = default
            optional = True
        self.optional = optional

    def _strptime_bered(self, value):
        year, month, day, hour, minute, _ = str_to_time_fractions(value[:10] + "00")
        value = value[10:]
        if len(value) == 0:
            raise ValueError("no timezone")
        year += 2000 if year < 50 else 1900
        decoded = datetime(year, month, day, hour, minute)
        offset = 0
        if value[-1] == "Z":
            value = value[:-1]
        else:
            if len(value) < 5:
                raise ValueError("invalid UTC offset")
            if value[-5] == "-":
                sign = -1
            elif value[-5] == "+":
                sign = 1
            else:
                raise ValueError("invalid UTC offset")
            v = pureint(value[-4:])
            offset, v = (60 * (v % 100)), v // 100
            if offset >= 3600:
                raise ValueError("invalid UTC offset minutes")
            offset += 3600 * v
            if offset > 14 * 3600:
                raise ValueError("too big UTC offset")
            offset *= sign
            value = value[:-5]
        if len(value) == 0:
            return offset, decoded
        if len(value) != 2:
            raise ValueError("invalid UTC offset seconds")
        seconds = pureint(value)
        if seconds >= 60:
            raise ValueError("invalid seconds value")
        return offset, decoded + timedelta(seconds=seconds)

    def _strptime(self, value):
        # datetime.strptime's format: %y%m%d%H%M%SZ
        if len(value) != LEN_YYMMDDHHMMSSZ:
            raise ValueError("invalid UTCTime length")
        if value[-1] != "Z":
            raise ValueError("non UTC timezone")
        year, month, day, hour, minute, second = str_to_time_fractions(value[:-1])
        year += 2000 if year < 50 else 1900
        return datetime(year, month, day, hour, minute, second)

    def _dt_sanitize(self, value):
        if value.year < 1950 or value.year > 2049:
            raise ValueError("UTCTime can hold only 1950-2049 years")
        return value.replace(microsecond=0)

    def _value_sanitize(self, value, ctx=None):
        if value.__class__ == bytes:
            try:
                value_decoded = value.decode("ascii")
            except (UnicodeEncodeError, UnicodeDecodeError) as err:
                raise DecodeError("invalid UTCTime encoding: %r" % err)
            err = None
            try:
                return self._strptime(value_decoded), None
            except (TypeError, ValueError) as _err:
                err = _err
                if (ctx is not None) and ctx.get("bered", False):
                    try:
                        offset, _value = self._strptime_bered(value_decoded)
                        _value = _value - timedelta(seconds=offset)
                        return self._dt_sanitize(_value), value
                    except (TypeError, ValueError, OverflowError) as _err:
                        err = _err
            raise DecodeError(
                "invalid %s format: %r" % (self.asn1_type_name, err),
                klass=self.__class__,
            )
        if isinstance(value, self.__class__):
            return value._value, None
        if value.__class__ == datetime:
            if value.tzinfo is not None:
                raise ValueError("only naive datetime supported")
            return self._dt_sanitize(value), None
        raise InvalidValueType((self.__class__, datetime))

    def _pp_value(self):
        if self.ready:
            value = self._value.isoformat()
            if self.ber_encoded:
                value += " (%s)" % self.ber_raw
            return value
        return None

    def __unicode__(self):
        if self.ready:
            value = self._value.isoformat()
            if self.ber_encoded:
                value += " (%s)" % self.ber_raw
            return value
        return str(self._pp_value())

    def __getstate__(self):
        return UTCTimeState(*super().__getstate__(), **{"ber_raw": self.ber_raw})

    def __setstate__(self, state):
        super().__setstate__(state)
        self.ber_raw = state.ber_raw

    def __bytes__(self):
        self._assert_ready()
        return self._encode_time()

    def __eq__(self, their):
        if their.__class__ == bytes:
            return self._encode_time() == their
        if their.__class__ == datetime:
            return self.todatetime() == their
        if not isinstance(their, self.__class__):
            return False
        return (
            self._value == their._value and
            self.tag == their.tag and
            self._expl == their._expl
        )

    def _encode_time(self):
        return self._value.strftime("%y%m%d%H%M%SZ").encode("ascii")

    def _encode(self):
        self._assert_ready()
        return b"".join((self.tag, LEN_LEN_YYMMDDHHMMSSZ, self._encode_time()))

    def _encode1st(self, state):
        return len(self.tag) + LEN_YYMMDDHHMMSSZ_WITH_LEN, state

    def _encode2nd(self, writer, state_iter):
        self._assert_ready()
        write_full(writer, self._encode())

    def _encode_cer(self, writer):
        write_full(writer, self._encode())

    def todatetime(self):
        return self._value

    def totzdatetime(self):
        try:
            return self._value.replace(tzinfo=tzUTC)
        except TypeError as err:
            raise NotImplementedError("Missing dateutil.tz") from err

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=self._pp_value(),
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for pp in self.pps_lenindef(decode_path):
            yield pp


class GeneralizedTime(UTCTime):
    """``GeneralizedTime`` datetime type

    This type is similar to :py:class:`pyderasn.UTCTime`.

    >>> t = GeneralizedTime(datetime(2017, 9, 30, 22, 7, 50, 123))
    GeneralizedTime GeneralizedTime 2017-09-30T22:07:50.000123
    >>> str(t)
    '20170930220750.000123Z'
    >>> t = GeneralizedTime(datetime(2057, 9, 30, 22, 7, 50))
    GeneralizedTime GeneralizedTime 2057-09-30T22:07:50

    .. warning::

       Only **naive** datetime objects are supported.
       Library assumes that all work is done in UTC.

    .. warning::

       Only **microsecond** fractions are supported in DER encoding.
       :py:exc:`pyderasn.DecodeError` will be raised during decoding of
       higher precision values.

    .. warning::

       **BER** encoded data can loss information (accuracy) during
       decoding because of float transformations.

    .. warning::

       **Zero** year is unsupported.
    """
    __slots__ = ()
    tag_default = tag_encode(24)
    asn1_type_name = "GeneralizedTime"

    def _dt_sanitize(self, value):
        return value

    def _strptime_bered(self, value):
        if len(value) < 4 + 3 * 2:
            raise ValueError("invalid GeneralizedTime")
        year, month, day, hour, _, _ = str_to_time_fractions(value[:10] + "0000")
        decoded = datetime(year, month, day, hour)
        offset, value = 0, value[10:]
        if len(value) == 0:
            return offset, decoded
        if value[-1] == "Z":
            value = value[:-1]
        else:
            for char, sign in (("-", -1), ("+", 1)):
                idx = value.rfind(char)
                if idx == -1:
                    continue
                offset_raw, value = value[idx + 1:].replace(":", ""), value[:idx]
                v = pureint(offset_raw)
                if len(offset_raw) == 4:
                    offset, v = (60 * (v % 100)), v // 100
                    if offset >= 3600:
                        raise ValueError("invalid UTC offset minutes")
                elif len(offset_raw) == 2:
                    pass
                else:
                    raise ValueError("invalid UTC offset")
                offset += 3600 * v
                if offset > 14 * 3600:
                    raise ValueError("too big UTC offset")
                offset *= sign
                break
        if len(value) == 0:
            return offset, decoded
        if value[0] in DECIMAL_SIGNS:
            return offset, (
                decoded + timedelta(seconds=3600 * fractions2float(value[1:]))
            )
        if len(value) < 2:
            raise ValueError("stripped minutes")
        decoded += timedelta(seconds=60 * pureint(value[:2]))
        value = value[2:]
        if len(value) == 0:
            return offset, decoded
        if value[0] in DECIMAL_SIGNS:
            return offset, (
                decoded + timedelta(seconds=60 * fractions2float(value[1:]))
            )
        if len(value) < 2:
            raise ValueError("stripped seconds")
        decoded += timedelta(seconds=pureint(value[:2]))
        value = value[2:]
        if len(value) == 0:
            return offset, decoded
        if value[0] not in DECIMAL_SIGNS:
            raise ValueError("invalid format after seconds")
        return offset, (
            decoded + timedelta(microseconds=10**6 * fractions2float(value[1:]))
        )

    def _strptime(self, value):
        l = len(value)
        if l == LEN_YYYYMMDDHHMMSSZ:
            # datetime.strptime's format: %Y%m%d%H%M%SZ
            if value[-1] != "Z":
                raise ValueError("non UTC timezone")
            return datetime(*str_to_time_fractions(value[:-1]))
        if l >= LEN_YYYYMMDDHHMMSSDMZ:
            # datetime.strptime's format: %Y%m%d%H%M%S.%fZ
            if value[-1] != "Z":
                raise ValueError("non UTC timezone")
            if value[14] != ".":
                raise ValueError("no fractions separator")
            us = value[15:-1]
            if us[-1] == "0":
                raise ValueError("trailing zero")
            us_len = len(us)
            if us_len > 6:
                raise ValueError("only microsecond fractions are supported")
            us = pureint(us + ("0" * (6 - us_len)))
            year, month, day, hour, minute, second = str_to_time_fractions(value[:14])
            return datetime(year, month, day, hour, minute, second, us)
        raise ValueError("invalid GeneralizedTime length")

    def _encode_time(self):
        value = self._value
        encoded = value.strftime("%Y%m%d%H%M%S")
        if value.microsecond > 0:
            encoded += (".%06d" % value.microsecond).rstrip("0")
        return (encoded + "Z").encode("ascii")

    def _encode(self):
        self._assert_ready()
        value = self._value
        if value.microsecond > 0:
            encoded = self._encode_time()
            return b"".join((self.tag, len_encode(len(encoded)), encoded))
        return b"".join((self.tag, LEN_LEN_YYYYMMDDHHMMSSZ, self._encode_time()))

    def _encode1st(self, state):
        self._assert_ready()
        vlen = len(self._encode_time())
        return len(self.tag) + len_size(vlen) + vlen, state

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self._encode())


class GraphicString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(25)
    encoding = "iso-8859-1"
    asn1_type_name = "GraphicString"


class GeneralString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(27)
    encoding = "iso-8859-1"
    asn1_type_name = "GeneralString"


class UniversalString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(28)
    encoding = "utf-32-be"
    asn1_type_name = "UniversalString"


class BMPString(CommonString):
    __slots__ = ()
    tag_default = tag_encode(30)
    encoding = "utf-16-be"
    asn1_type_name = "BMPString"


ChoiceState = namedtuple(
    "ChoiceState",
    BasicState._fields + ("specs", "value",),
    **NAMEDTUPLE_KWARGS
)


class Choice(Obj):
    """``CHOICE`` special type

    ::

        class GeneralName(Choice):
            schema = (
                ("rfc822Name", IA5String(impl=tag_ctxp(1))),
                ("dNSName", IA5String(impl=tag_ctxp(2))),
            )

    >>> gn = GeneralName()
    GeneralName CHOICE
    >>> gn["rfc822Name"] = IA5String("foo@bar.baz")
    GeneralName CHOICE rfc822Name[[1] IA5String IA5 foo@bar.baz]
    >>> gn["dNSName"] = IA5String("bar.baz")
    GeneralName CHOICE dNSName[[2] IA5String IA5 bar.baz]
    >>> gn["rfc822Name"]
    None
    >>> gn["dNSName"]
    [2] IA5String IA5 bar.baz
    >>> gn.choice
    'dNSName'
    >>> gn.value == gn["dNSName"]
    True
    >>> gn.specs
    OrderedDict([('rfc822Name', [1] IA5String IA5), ('dNSName', [2] IA5String IA5)])

    >>> GeneralName(("rfc822Name", IA5String("foo@bar.baz")))
    GeneralName CHOICE rfc822Name[[1] IA5String IA5 foo@bar.baz]
    """
    __slots__ = ("specs",)
    tag_default = None
    asn1_type_name = "CHOICE"

    def __init__(
            self,
            value=None,
            schema=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either ``(choice, value)`` tuple, or
                      :py:class:`pyderasn.Choice` object
        :param bytes impl: can not be set, do **not** use it
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param default: set default value. Type same as in ``value``
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        if impl is not None:
            raise ValueError("no implicit tag allowed for CHOICE")
        super().__init__(None, expl, default, optional, _decoded)
        if schema is None:
            schema = getattr(self, "schema", ())
        if len(schema) == 0:
            raise ValueError("schema must be specified")
        self.specs = (
            schema if schema.__class__ == OrderedDict else OrderedDict(schema)
        )
        self._value = None
        if value is not None:
            self._value = self._value_sanitize(value)
        if default is not None:
            default_value = self._value_sanitize(default)
            default_obj = self.__class__(impl=self.tag, expl=self._expl)
            default_obj.specs = self.specs
            default_obj._value = default_value
            self.default = default_obj
            if value is None:
                self._value = copy(default_obj._value)
        if self._expl is not None:
            tag_class, _, tag_num = tag_decode(self._expl)
            self._tag_order = (tag_class, tag_num)

    def _value_sanitize(self, value):
        if (value.__class__ == tuple) and len(value) == 2:
            choice, obj = value
            spec = self.specs.get(choice)
            if spec is None:
                raise ObjUnknown(choice)
            if not isinstance(obj, spec.__class__):
                raise InvalidValueType((spec,))
            return (choice, spec(obj))
        if isinstance(value, self.__class__):
            return value._value
        raise InvalidValueType((self.__class__, tuple))

    @property
    def ready(self):
        return self._value is not None and self._value[1].ready

    @property
    def bered(self):
        return self.expl_lenindef or (
            (self._value is not None) and
            self._value[1].bered
        )

    def __getstate__(self):
        return ChoiceState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self.specs,
            copy(self._value),
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self.specs = state.specs
        self._value = state.value

    def __eq__(self, their):
        if (their.__class__ == tuple) and len(their) == 2:
            return self._value == their
        if not isinstance(their, self.__class__):
            return False
        return (
            self.specs == their.specs and
            self._value == their._value
        )

    def __call__(
            self,
            value=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            schema=self.specs,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    @property
    def choice(self):
        """Name of the choice
        """
        self._assert_ready()
        return self._value[0]

    @property
    def value(self):
        """Value of underlying choice
        """
        self._assert_ready()
        return self._value[1]

    @property
    def tag_order(self):
        self._assert_ready()
        return self._value[1].tag_order if self._tag_order is None else self._tag_order

    @property
    def tag_order_cer(self):
        return min(v.tag_order_cer for v in self.specs.values())

    def __getitem__(self, key):
        if key not in self.specs:
            raise ObjUnknown(key)
        if self._value is None:
            return None
        choice, value = self._value
        if choice != key:
            return None
        return value

    def __setitem__(self, key, value):
        spec = self.specs.get(key)
        if spec is None:
            raise ObjUnknown(key)
        if not isinstance(value, spec.__class__):
            raise InvalidValueType((spec.__class__,))
        self._value = (key, spec(value))

    @property
    def tlen(self):
        return 0

    @property
    def decoded(self):
        return self._value[1].decoded if self.ready else False

    def _encode(self):
        self._assert_ready()
        return self._value[1].encode()

    def _encode1st(self, state):
        self._assert_ready()
        return self._value[1].encode1st(state)

    def _encode2nd(self, writer, state_iter):
        self._value[1].encode2nd(writer, state_iter)

    def _encode_cer(self, writer):
        self._assert_ready()
        self._value[1].encode_cer(writer)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        for choice, spec in self.specs.items():
            sub_decode_path = decode_path + (choice,)
            try:
                spec.decode(
                    tlv,
                    offset=offset,
                    leavemm=True,
                    decode_path=sub_decode_path,
                    ctx=ctx,
                    tag_only=True,
                    _ctx_immutable=False,
                )
            except TagMismatch:
                continue
            break
        else:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:  # pragma: no cover
            yield None
            return
        if evgen_mode:
            for _decode_path, value, tail in spec.decode_evgen(
                    tlv,
                    offset=offset,
                    leavemm=True,
                    decode_path=sub_decode_path,
                    ctx=ctx,
                    _ctx_immutable=False,
            ):
                yield _decode_path, value, tail
        else:
            _, value, tail = next(spec.decode_evgen(
                tlv,
                offset=offset,
                leavemm=True,
                decode_path=sub_decode_path,
                ctx=ctx,
                _ctx_immutable=False,
                _evgen_mode=False,
            ))
        obj = self.__class__(
            schema=self.specs,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _decoded=(offset, 0, value.fulllen),
        )
        obj._value = (choice, value)
        yield decode_path, obj, tail

    def __repr__(self):
        value = pp_console_row(next(self.pps()))
        if self.ready:
            value = "%s[%r]" % (value, self.value)
        return value

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=self.choice if self.ready else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_lenindef=self.expl_lenindef,
            bered=self.bered,
        )
        if self.ready:
            yield self.value.pps(decode_path=decode_path + (self.choice,))
        for pp in self.pps_lenindef(decode_path):
            yield pp


class PrimitiveTypes(Choice):
    """Predefined ``CHOICE`` for all generic primitive types

    It could be useful for general decoding of some unspecified values:

    >>> PrimitiveTypes().decod(hexdec("0403666f6f")).value
    OCTET STRING 3 bytes 666f6f
    >>> PrimitiveTypes().decod(hexdec("0203123456")).value
    INTEGER 1193046
    """
    __slots__ = ()
    schema = tuple((klass.__name__, klass()) for klass in (
        Boolean,
        Integer,
        BitString,
        OctetString,
        Null,
        ObjectIdentifier,
        UTF8String,
        NumericString,
        PrintableString,
        TeletexString,
        VideotexString,
        IA5String,
        UTCTime,
        GeneralizedTime,
        GraphicString,
        VisibleString,
        ISO646String,
        GeneralString,
        UniversalString,
        BMPString,
    ))


AnyState = namedtuple(
    "AnyState",
    BasicState._fields + ("value", "defined"),
    **NAMEDTUPLE_KWARGS
)


class Any(Obj):
    """``ANY`` special type

    >>> Any(Integer(-123))
    ANY INTEGER -123 (0X:7B)
    >>> a = Any(OctetString(b"hello world").encode())
    ANY 040b68656c6c6f20776f726c64
    >>> hexenc(bytes(a))
    b'0x040x0bhello world'
    """
    __slots__ = ("defined",)
    tag_default = tag_encode(0)
    asn1_type_name = "ANY"

    def __init__(
            self,
            value=None,
            expl=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        """
        :param value: set the value. Either any kind of pyderasn's
                      **ready** object, or bytes. Pay attention that
                      **no** validation is performed if raw binary value
                      is valid TLV, except just tag decoding
        :param bytes expl: override default tag with ``EXPLICIT`` one
        :param bool optional: is object ``OPTIONAL`` in sequence
        """
        super().__init__(None, expl, None, optional, _decoded)
        if value is None:
            self._value = None
        else:
            value = self._value_sanitize(value)
            self._value = value
            if self._expl is None:
                if value.__class__ == bytes or value.__class__ == memoryview:
                    tag_class, _, tag_num = tag_decode(tag_strip(value)[0])
                else:
                    tag_class, tag_num = value.tag_order
            else:
                tag_class, _, tag_num = tag_decode(self._expl)
            self._tag_order = (tag_class, tag_num)
        self.defined = None

    def _value_sanitize(self, value):
        if value.__class__ == bytes or value.__class__ == memoryview:
            if len(value) == 0:
                raise ValueError("%s value can not be empty" % self.__class__.__name__)
            return value
        if isinstance(value, self.__class__):
            return value._value
        if not isinstance(value, Obj):
            raise InvalidValueType((self.__class__, Obj, bytes))
        return value

    @property
    def ready(self):
        return self._value is not None

    @property
    def tag_order(self):
        self._assert_ready()
        return self._tag_order

    @property
    def bered(self):
        if self.expl_lenindef or self.lenindef:
            return True
        if self.defined is None:
            return False
        return self.defined[1].bered

    def __getstate__(self):
        return AnyState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            None,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self._value,
            self.defined,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self._value = state.value
        self.defined = state.defined

    def __eq__(self, their):
        if their.__class__ == bytes or their.__class__ == memoryview:
            if self._value.__class__ == bytes or their.__class__ == memoryview:
                return self._value == their
            return self._value.encode() == their
        if issubclass(their.__class__, Any):
            if self.ready and their.ready:
                return self.memoryview() == their.memoryview()
            return self.ready == their.ready
        return False

    def __call__(
            self,
            value=None,
            expl=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            expl=self._expl if expl is None else expl,
            optional=self.optional if optional is None else optional,
        )

    def __bytes__(self):
        self._assert_ready()
        value = self._value
        if value.__class__ == bytes:
            return value
        if value.__class__ == memoryview:
            return bytes(value)
        return self._value.encode()

    def memoryview(self):
        self._assert_ready()
        value = self._value
        if value.__class__ == memoryview:
            return memoryview(value)
        return memoryview(bytes(self))

    @property
    def tlen(self):
        return 0

    def _encode(self):
        self._assert_ready()
        value = self._value
        if value.__class__ == bytes or value.__class__ == memoryview:
            return bytes(self)
        return value.encode()

    def _encode1st(self, state):
        self._assert_ready()
        value = self._value
        if value.__class__ == bytes or value.__class__ == memoryview:
            return len(value), state
        return value.encode1st(state)

    def _encode2nd(self, writer, state_iter):
        value = self._value
        if value.__class__ == bytes or value.__class__ == memoryview:
            write_full(writer, value)
        else:
            value.encode2nd(writer, state_iter)

    def _encode_cer(self, writer):
        self._assert_ready()
        value = self._value
        if value.__class__ == bytes or value.__class__ == memoryview:
            write_full(writer, value)
        else:
            value.encode_cer(writer)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm as err:
            if not ctx.get("bered", False):
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            llen, vlen, v = 1, 0, lv[1:]
            sub_offset = offset + tlen + llen
            chunk_i = 0
            while v[:EOC_LEN].tobytes() != EOC:
                chunk, v = Any().decode(
                    v,
                    offset=sub_offset,
                    decode_path=decode_path + (str(chunk_i),),
                    leavemm=True,
                    ctx=ctx,
                    _ctx_immutable=False,
                )
                vlen += chunk.tlvlen
                sub_offset += chunk.tlvlen
                chunk_i += 1
            tlvlen = tlen + llen + vlen + EOC_LEN
            obj = self.__class__(
                value=None if evgen_mode else tlv[:tlvlen].tobytes(),
                expl=self._expl,
                optional=self.optional,
                _decoded=(offset, 0, tlvlen),
            )
            obj.lenindef = True
            obj.tag = t.tobytes()
            yield decode_path, obj, v[EOC_LEN:]
            return
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        tlvlen = tlen + llen + l
        v, tail = tlv[:tlvlen], v[l:]
        if evgen_mode:
            value = None
        elif ctx.get("keep_memoryview", False):
            value = v
        else:
            value = v.tobytes()
        obj = self.__class__(
            value=value,
            expl=self._expl,
            optional=self.optional,
            _decoded=(offset, 0, tlvlen),
        )
        obj.tag = t.tobytes()
        yield decode_path, obj, tail

    def __repr__(self):
        return pp_console_row(next(self.pps()))

    def pps(self, decode_path=()):
        value = self._value
        if value is None:
            pass
        elif value.__class__ == bytes or value.__class__ == memoryview:
            value = None
        else:
            value = repr(value)
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            value=value,
            blob=self._value if (
                self._value.__class__ == bytes or
                value.__class__ == memoryview
            ) else None,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            lenindef=self.lenindef,
            bered=self.bered,
        )
        defined_by, defined = self.defined or (None, None)
        if defined_by is not None:
            yield defined.pps(
                decode_path=decode_path + (DecodePathDefBy(defined_by),)
            )
        for pp in self.pps_lenindef(decode_path):
            yield pp


########################################################################
# ASN.1 constructed types
########################################################################

def abs_decode_path(decode_path, rel_path):
    """Create an absolute decode path from current and relative ones

    :param decode_path: current decode path, starting point. Tuple of strings
    :param rel_path: relative path to ``decode_path``. Tuple of strings.
                     If first tuple's element is "/", then treat it as
                     an absolute path, ignoring ``decode_path`` as
                     starting point. Also this tuple can contain ".."
                     elements, stripping the leading element from
                     ``decode_path``

    >>> abs_decode_path(("foo", "bar"), ("baz", "whatever"))
    ("foo", "bar", "baz", "whatever")
    >>> abs_decode_path(("foo", "bar", "baz"), ("..", "..", "whatever"))
    ("foo", "whatever")
    >>> abs_decode_path(("foo", "bar"), ("/", "baz", "whatever"))
    ("baz", "whatever")
    """
    if rel_path[0] == "/":
        return rel_path[1:]
    if rel_path[0] == "..":
        return abs_decode_path(decode_path[:-1], rel_path[1:])
    return decode_path + rel_path


SequenceState = namedtuple(
    "SequenceState",
    BasicState._fields + ("specs", "value",),
    **NAMEDTUPLE_KWARGS
)


class SequenceEncode1stMixin:
    __slots__ = ()

    def _encode1st(self, state):
        state.append(0)
        idx = len(state) - 1
        vlen = 0
        for v in self._values_for_encoding():
            l, _ = v.encode1st(state)
            vlen += l
        state[idx] = vlen
        return len(self.tag) + len_size(vlen) + vlen, state


class Sequence(SequenceEncode1stMixin, Obj):
    """``SEQUENCE`` structure type

    You have to make specification of sequence::

        class Extension(Sequence):
            schema = (
                ("extnID", ObjectIdentifier()),
                ("critical", Boolean(default=False)),
                ("extnValue", OctetString()),
            )

    Then, you can work with it as with dictionary.

    >>> ext = Extension()
    >>> Extension().specs
    OrderedDict([
        ('extnID', OBJECT IDENTIFIER),
        ('critical', BOOLEAN False OPTIONAL DEFAULT),
        ('extnValue', OCTET STRING),
    ])
    >>> ext["extnID"] = "1.2.3"
    Traceback (most recent call last):
    pyderasn.InvalidValueType: invalid value type, expected: <class 'pyderasn.ObjectIdentifier'>
    >>> ext["extnID"] = ObjectIdentifier("1.2.3")

    You can determine if sequence is ready to be encoded:

    >>> ext.ready
    False
    >>> ext.encode()
    Traceback (most recent call last):
    pyderasn.ObjNotReady: object is not ready: extnValue
    >>> ext["extnValue"] = OctetString(b"foobar")
    >>> ext.ready
    True

    Value you want to assign, must have the same **type** as in
    corresponding specification, but it can have different tags,
    optional/default attributes -- they will be taken from specification
    automatically::

        class TBSCertificate(Sequence):
            schema = (
                ("version", Version(expl=tag_ctxc(0), default="v1")),
            [...]

    >>> tbs = TBSCertificate()
    >>> tbs["version"] = Version("v2") # no need to explicitly add ``expl``

    Assign ``None`` to remove value from sequence.

    You can set values in Sequence during its initialization:

    >>> AlgorithmIdentifier((
        ("algorithm", ObjectIdentifier("1.2.3")),
        ("parameters", Any(Null()))
    ))
    AlgorithmIdentifier SEQUENCE[algorithm: OBJECT IDENTIFIER 1.2.3; parameters: ANY 0500 OPTIONAL]

    You can determine if value exists/set in the sequence and take its value:

    >>> "extnID" in ext, "extnValue" in ext, "critical" in ext
    (True, True, False)
    >>> ext["extnID"]
    OBJECT IDENTIFIER 1.2.3

    But pay attention that if value has default, then it won't be (not
    in) in the sequence (because ``DEFAULT`` must not be encoded in
    DER), but you can read its value:

    >>> "critical" in ext, ext["critical"]
    (False, BOOLEAN False)
    >>> ext["critical"] = Boolean(True)
    >>> "critical" in ext, ext["critical"]
    (True, BOOLEAN True)

    All defaulted values are always optional.

    .. _allow_default_values_ctx:

    DER prohibits default value encoding and will raise an error if
    default value is unexpectedly met during decode.
    If :ref:`bered <bered_ctx>` context option is set, then no error
    will be raised, but ``bered`` attribute set. You can disable strict
    defaulted values existence validation by setting
    ``"allow_default_values": True`` :ref:`context <ctx>` option.

    All values with DEFAULT specified are decoded atomically in
    :ref:`evgen mode <evgen_mode>`. If DEFAULT value is some kind of
    SEQUENCE, then it will be yielded as a single element, not
    disassembled. That is required for DEFAULT existence check.

    Two sequences are equal if they have equal specification (schema),
    implicit/explicit tagging and the same values.
    """
    __slots__ = ("specs",)
    tag_default = tag_encode(form=TagFormConstructed, num=16)
    asn1_type_name = "SEQUENCE"

    def __init__(
            self,
            value=None,
            schema=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        super().__init__(impl, expl, default, optional, _decoded)
        if schema is None:
            schema = getattr(self, "schema", ())
        self.specs = (
            schema if schema.__class__ == OrderedDict else OrderedDict(schema)
        )
        self._value = {}
        if value is not None:
            if issubclass(value.__class__, Sequence):
                self._value = value._value
            elif hasattr(value, "__iter__"):
                for seq_key, seq_value in value:
                    self[seq_key] = seq_value
            else:
                raise InvalidValueType((Sequence,))
        if default is not None:
            if not issubclass(default.__class__, Sequence):
                raise InvalidValueType((Sequence,))
            default_value = default._value
            default_obj = self.__class__(impl=self.tag, expl=self._expl)
            default_obj.specs = self.specs
            default_obj._value = default_value
            self.default = default_obj
            if value is None:
                self._value = copy(default_obj._value)

    @property
    def ready(self):
        for name, spec in self.specs.items():
            value = self._value.get(name)
            if value is None:
                if spec.optional:
                    continue
                return False
            if not value.ready:
                return False
        return True

    @property
    def bered(self):
        if self.expl_lenindef or self.lenindef or self.ber_encoded:
            return True
        return any(value.bered for value in self._value.values())

    def __getstate__(self):
        return SequenceState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self.specs,
            {k: copy(v) for k, v in self._value.items()},
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self.specs = state.specs
        self._value = state.value

    def __eq__(self, their):
        if not isinstance(their, self.__class__):
            return False
        return (
            self.specs == their.specs and
            self.tag == their.tag and
            self._expl == their._expl and
            self._value == their._value
        )

    def __call__(
            self,
            value=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            schema=self.specs,
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    def __contains__(self, key):
        return key in self._value

    def __setitem__(self, key, value):
        spec = self.specs.get(key)
        if spec is None:
            raise ObjUnknown(key)
        if value is None:
            self._value.pop(key, None)
            return
        if not isinstance(value, spec.__class__):
            raise InvalidValueType((spec.__class__,))
        value = spec(value=value)
        if spec.default is not None and value == spec.default:
            self._value.pop(key, None)
            return
        self._value[key] = value

    def __getitem__(self, key):
        value = self._value.get(key)
        if value is not None:
            return value
        spec = self.specs.get(key)
        if spec is None:
            raise ObjUnknown(key)
        if spec.default is not None:
            return spec.default
        return None

    def _values_for_encoding(self):
        for name, spec in self.specs.items():
            value = self._value.get(name)
            if value is None:
                if spec.optional:
                    continue
                raise ObjNotReady(name)
            yield value

    def _encode(self):
        v = b"".join(v.encode() for v in self._values_for_encoding())
        return b"".join((self.tag, len_encode(len(v)), v))

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self.tag + len_encode(next(state_iter)))
        for v in self._values_for_encoding():
            v.encode2nd(writer, state_iter)

    def _encode_cer(self, writer):
        write_full(writer, self.tag + LENINDEF)
        for v in self._values_for_encoding():
            v.encode_cer(writer)
        write_full(writer, EOC)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:  # pragma: no cover
            yield None
            return
        lenindef = False
        ctx_bered = ctx.get("bered", False)
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm as err:
            if not ctx_bered:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            l, llen, v = 0, 1, lv[1:]
            lenindef = True
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if not lenindef:
            v, tail = v[:l], v[l:]
        vlen = 0
        sub_offset = offset + tlen + llen
        values = {}
        ber_encoded = False
        ctx_allow_default_values = ctx.get("allow_default_values", False)
        for name, spec in self.specs.items():
            if spec.optional and (
                    (lenindef and v[:EOC_LEN].tobytes() == EOC) or
                    len(v) == 0
            ):
                continue
            spec_defaulted = spec.default is not None
            sub_decode_path = decode_path + (name,)
            try:
                if evgen_mode and not spec_defaulted:
                    for _decode_path, value, v_tail in spec.decode_evgen(
                            v,
                            sub_offset,
                            leavemm=True,
                            decode_path=sub_decode_path,
                            ctx=ctx,
                            _ctx_immutable=False,
                    ):
                        yield _decode_path, value, v_tail
                else:
                    _, value, v_tail = next(spec.decode_evgen(
                        v,
                        sub_offset,
                        leavemm=True,
                        decode_path=sub_decode_path,
                        ctx=ctx,
                        _ctx_immutable=False,
                        _evgen_mode=False,
                    ))
            except TagMismatch as err:
                if (len(err.decode_path) == len(decode_path) + 1) and spec.optional:
                    continue
                raise

            defined = get_def_by_path(ctx.get("_defines", ()), sub_decode_path)
            if not evgen_mode and defined is not None:
                defined_by, defined_spec = defined
                if issubclass(value.__class__, SequenceOf):
                    for i, _value in enumerate(value):
                        sub_sub_decode_path = sub_decode_path + (
                            str(i),
                            DecodePathDefBy(defined_by),
                        )
                        defined_value, defined_tail = defined_spec.decode(
                            memoryview(bytes(_value)),
                            sub_offset + (
                                (value.tlen + value.llen + value.expl_tlen + value.expl_llen)
                                if value.expled else (value.tlen + value.llen)
                            ),
                            leavemm=True,
                            decode_path=sub_sub_decode_path,
                            ctx=ctx,
                            _ctx_immutable=False,
                        )
                        if len(defined_tail) > 0:
                            raise DecodeError(
                                "remaining data",
                                klass=self.__class__,
                                decode_path=sub_sub_decode_path,
                                offset=offset,
                            )
                        _value.defined = (defined_by, defined_value)
                else:
                    defined_value, defined_tail = defined_spec.decode(
                        memoryview(bytes(value)),
                        sub_offset + (
                            (value.tlen + value.llen + value.expl_tlen + value.expl_llen)
                            if value.expled else (value.tlen + value.llen)
                        ),
                        leavemm=True,
                        decode_path=sub_decode_path + (DecodePathDefBy(defined_by),),
                        ctx=ctx,
                        _ctx_immutable=False,
                    )
                    if len(defined_tail) > 0:
                        raise DecodeError(
                            "remaining data",
                            klass=self.__class__,
                            decode_path=sub_decode_path + (DecodePathDefBy(defined_by),),
                            offset=offset,
                        )
                    value.defined = (defined_by, defined_value)

            value_len = value.fulllen
            vlen += value_len
            sub_offset += value_len
            v = v_tail
            if spec_defaulted:
                if evgen_mode:
                    yield sub_decode_path, value, v_tail
                if value == spec.default:
                    if ctx_bered or ctx_allow_default_values:
                        ber_encoded = True
                    else:
                        raise DecodeError(
                            "DEFAULT value met",
                            klass=self.__class__,
                            decode_path=sub_decode_path,
                            offset=sub_offset,
                        )
            if not evgen_mode:
                values[name] = value
                spec_defines = getattr(spec, "defines", ())
                if len(spec_defines) == 0:
                    defines_by_path = ctx.get("defines_by_path", ())
                    if len(defines_by_path) > 0:
                        spec_defines = get_def_by_path(defines_by_path, sub_decode_path)
                if spec_defines is not None and len(spec_defines) > 0:
                    for rel_path, schema in spec_defines:
                        defined = schema.get(value, None)
                        if defined is not None:
                            ctx.setdefault("_defines", []).append((
                                abs_decode_path(sub_decode_path[:-1], rel_path),
                                (value, defined),
                            ))
        if lenindef:
            if v[:EOC_LEN].tobytes() != EOC:
                raise DecodeError(
                    "no EOC",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            tail = v[EOC_LEN:]
            vlen += EOC_LEN
        elif len(v) > 0:
            raise DecodeError(
                "remaining data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        obj = self.__class__(
            schema=self.specs,
            impl=self.tag,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _decoded=(offset, llen, vlen),
        )
        obj._value = values
        obj.lenindef = lenindef
        obj.ber_encoded = ber_encoded
        yield decode_path, obj, tail

    def __repr__(self):
        value = pp_console_row(next(self.pps()))
        cols = []
        for name in self.specs:
            _value = self._value.get(name)
            if _value is None:
                continue
            cols.append("%s: %s" % (name, repr(_value)))
        return "%s[%s]" % (value, "; ".join(cols))

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            lenindef=self.lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for name in self.specs:
            value = self._value.get(name)
            if value is None:
                continue
            yield value.pps(decode_path=decode_path + (name,))
        for pp in self.pps_lenindef(decode_path):
            yield pp


class Set(Sequence, SequenceEncode1stMixin):
    """``SET`` structure type

    Its usage is identical to :py:class:`pyderasn.Sequence`.

    .. _allow_unordered_set_ctx:

    DER prohibits unordered values encoding and will raise an error
    during decode. If :ref:`bered <bered_ctx>` context option is set,
    then no error will occur. Also you can disable strict values
    ordering check by setting ``"allow_unordered_set": True``
    :ref:`context <ctx>` option.
    """
    __slots__ = ()
    tag_default = tag_encode(form=TagFormConstructed, num=17)
    asn1_type_name = "SET"

    def _values_for_encoding(self):
        return sorted(super()._values_for_encoding(), key=attrgetter("tag_order"))

    def _encode_cer(self, writer):
        write_full(writer, self.tag + LENINDEF)
        for v in sorted(
                super()._values_for_encoding(),
                key=attrgetter("tag_order_cer"),
        ):
            v.encode_cer(writer)
        write_full(writer, EOC)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:
            yield None
            return
        lenindef = False
        ctx_bered = ctx.get("bered", False)
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm as err:
            if not ctx_bered:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            l, llen, v = 0, 1, lv[1:]
            lenindef = True
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                offset=offset,
            )
        if not lenindef:
            v, tail = v[:l], v[l:]
        vlen = 0
        sub_offset = offset + tlen + llen
        values = {}
        ber_encoded = False
        ctx_allow_default_values = ctx.get("allow_default_values", False)
        ctx_allow_unordered_set = ctx.get("allow_unordered_set", False)
        tag_order_prev = (0, 0)
        _specs_items = copy(self.specs)

        while len(v) > 0:
            if lenindef and v[:EOC_LEN].tobytes() == EOC:
                break
            for name, spec in _specs_items.items():
                sub_decode_path = decode_path + (name,)
                try:
                    spec.decode(
                        v,
                        sub_offset,
                        leavemm=True,
                        decode_path=sub_decode_path,
                        ctx=ctx,
                        tag_only=True,
                        _ctx_immutable=False,
                    )
                except TagMismatch:
                    continue
                break
            else:
                raise TagMismatch(
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            spec_defaulted = spec.default is not None
            if evgen_mode and not spec_defaulted:
                for _decode_path, value, v_tail in spec.decode_evgen(
                        v,
                        sub_offset,
                        leavemm=True,
                        decode_path=sub_decode_path,
                        ctx=ctx,
                        _ctx_immutable=False,
                ):
                    yield _decode_path, value, v_tail
            else:
                _, value, v_tail = next(spec.decode_evgen(
                    v,
                    sub_offset,
                    leavemm=True,
                    decode_path=sub_decode_path,
                    ctx=ctx,
                    _ctx_immutable=False,
                    _evgen_mode=False,
                ))
            value_tag_order = value.tag_order
            value_len = value.fulllen
            if tag_order_prev >= value_tag_order:
                if ctx_bered or ctx_allow_unordered_set:
                    ber_encoded = True
                else:
                    raise DecodeError(
                        "unordered " + self.asn1_type_name,
                        klass=self.__class__,
                        decode_path=sub_decode_path,
                        offset=sub_offset,
                    )
            if spec_defaulted:
                if evgen_mode:
                    yield sub_decode_path, value, v_tail
                if value != spec.default:
                    pass
                elif ctx_bered or ctx_allow_default_values:
                    ber_encoded = True
                else:
                    raise DecodeError(
                        "DEFAULT value met",
                        klass=self.__class__,
                        decode_path=sub_decode_path,
                        offset=sub_offset,
                    )
            values[name] = value
            del _specs_items[name]
            tag_order_prev = value_tag_order
            sub_offset += value_len
            vlen += value_len
            v = v_tail

        obj = self.__class__(
            schema=self.specs,
            impl=self.tag,
            expl=self._expl,
            default=self.default,
            optional=self.optional,
            _decoded=(offset, llen, vlen + (EOC_LEN if lenindef else 0)),
        )
        if lenindef:
            if v[:EOC_LEN].tobytes() != EOC:
                raise DecodeError(
                    "no EOC",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            tail = v[EOC_LEN:]
            obj.lenindef = True
        for name, spec in self.specs.items():
            if name not in values and not spec.optional:
                raise DecodeError(
                    "%s value is not ready" % name,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
        if not evgen_mode:
            obj._value = values
        obj.ber_encoded = ber_encoded
        yield decode_path, obj, tail


SequenceOfState = namedtuple(
    "SequenceOfState",
    BasicState._fields + ("spec", "value", "bound_min", "bound_max"),
    **NAMEDTUPLE_KWARGS
)


class SequenceOf(SequenceEncode1stMixin, Obj):
    """``SEQUENCE OF`` sequence type

    For that kind of type you must specify the object it will carry on
    (bounds are for example here, not required)::

        class Ints(SequenceOf):
            schema = Integer()
            bounds = (0, 2)

    >>> ints = Ints()
    >>> ints.append(Integer(123))
    >>> ints.append(Integer(234))
    >>> ints
    Ints SEQUENCE OF[INTEGER 123, INTEGER 234]
    >>> [int(i) for i in ints]
    [123, 234]
    >>> ints.append(Integer(345))
    Traceback (most recent call last):
    pyderasn.BoundsError: unsatisfied bounds: 0 <= 3 <= 2
    >>> ints[1]
    INTEGER 234
    >>> ints[1] = Integer(345)
    >>> ints
    Ints SEQUENCE OF[INTEGER 123, INTEGER 345]

    You can initialize sequence with preinitialized values:

    >>> ints = Ints([Integer(123), Integer(234)])

    Also you can use iterator as a value:

    >>> ints = Ints(iter(Integer(i) for i in range(1000000)))

    And it won't be iterated until encoding process. Pay attention that
    bounds and required schema checks are done only during the encoding
    process in that case! After encode was called, then value is zeroed
    back to empty list and you have to set it again. That mode is useful
    mainly with CER encoding mode, where all objects from the iterable
    will be streamed to the buffer, without copying all of them to
    memory first.
    """
    __slots__ = ("spec", "_bound_min", "_bound_max")
    tag_default = tag_encode(form=TagFormConstructed, num=16)
    asn1_type_name = "SEQUENCE OF"

    def __init__(
            self,
            value=None,
            schema=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=False,
            _decoded=(0, 0, 0),
    ):
        super().__init__(impl, expl, default, optional, _decoded)
        if schema is None:
            schema = getattr(self, "schema", None)
        if schema is None:
            raise ValueError("schema must be specified")
        self.spec = schema
        self._bound_min, self._bound_max = getattr(
            self,
            "bounds",
            (0, float("+inf")),
        ) if bounds is None else bounds
        self._value = []
        if value is not None:
            self._value = self._value_sanitize(value)
        if default is not None:
            default_value = self._value_sanitize(default)
            default_obj = self.__class__(
                schema=schema,
                impl=self.tag,
                expl=self._expl,
            )
            default_obj._value = default_value
            self.default = default_obj
            if value is None:
                self._value = copy(default_obj._value)

    def _value_sanitize(self, value):
        iterator = False
        if issubclass(value.__class__, SequenceOf):
            value = value._value
        elif hasattr(value, NEXT_ATTR_NAME):
            iterator = True
        elif hasattr(value, "__iter__"):
            value = list(value)
        else:
            raise InvalidValueType((self.__class__, iter, "iterator"))
        if not iterator:
            if not self._bound_min <= len(value) <= self._bound_max:
                raise BoundsError(self._bound_min, len(value), self._bound_max)
            class_expected = self.spec.__class__
            for v in value:
                if not isinstance(v, class_expected):
                    raise InvalidValueType((class_expected,))
        return value

    @property
    def ready(self):
        if hasattr(self._value, NEXT_ATTR_NAME):
            return True
        if self._bound_min > 0 and len(self._value) == 0:
            return False
        return all(v.ready for v in self._value)

    @property
    def bered(self):
        if self.expl_lenindef or self.lenindef or self.ber_encoded:
            return True
        return any(v.bered for v in self._value)

    def __getstate__(self):
        if hasattr(self._value, NEXT_ATTR_NAME):
            raise ValueError("can not pickle SequenceOf with iterator")
        return SequenceOfState(
            __version__,
            self.tag,
            self._tag_order,
            self._expl,
            self.default,
            self.optional,
            self.offset,
            self.llen,
            self.vlen,
            self.expl_lenindef,
            self.lenindef,
            self.ber_encoded,
            self.spec,
            [copy(v) for v in self._value],
            self._bound_min,
            self._bound_max,
        )

    def __setstate__(self, state):
        super().__setstate__(state)
        self.spec = state.spec
        self._value = state.value
        self._bound_min = state.bound_min
        self._bound_max = state.bound_max

    def __eq__(self, their):
        if isinstance(their, self.__class__):
            return (
                self.spec == their.spec and
                self.tag == their.tag and
                self._expl == their._expl and
                self._value == their._value
            )
        if hasattr(their, "__iter__"):
            return self._value == list(their)
        return False

    def __call__(
            self,
            value=None,
            bounds=None,
            impl=None,
            expl=None,
            default=None,
            optional=None,
    ):
        return self.__class__(
            value=value,
            schema=self.spec,
            bounds=(
                (self._bound_min, self._bound_max)
                if bounds is None else bounds
            ),
            impl=self.tag if impl is None else impl,
            expl=self._expl if expl is None else expl,
            default=self.default if default is None else default,
            optional=self.optional if optional is None else optional,
        )

    def __contains__(self, key):
        return key in self._value

    def append(self, value):
        if not isinstance(value, self.spec.__class__):
            raise InvalidValueType((self.spec.__class__,))
        if len(self._value) + 1 > self._bound_max:
            raise BoundsError(
                self._bound_min,
                len(self._value) + 1,
                self._bound_max,
            )
        self._value.append(value)

    def __iter__(self):
        return iter(self._value)

    def __len__(self):
        return len(self._value)

    def __setitem__(self, key, value):
        if not isinstance(value, self.spec.__class__):
            raise InvalidValueType((self.spec.__class__,))
        self._value[key] = self.spec(value=value)

    def __getitem__(self, key):
        return self._value[key]

    def _values_for_encoding(self):
        return iter(self._value)

    def _encode(self):
        iterator = hasattr(self._value, NEXT_ATTR_NAME)
        if iterator:
            values = []
            values_append = values.append
            class_expected = self.spec.__class__
            values_for_encoding = self._values_for_encoding()
            self._value = []
            for v in values_for_encoding:
                if not isinstance(v, class_expected):
                    raise InvalidValueType((class_expected,))
                values_append(v.encode())
            if not self._bound_min <= len(values) <= self._bound_max:
                raise BoundsError(self._bound_min, len(values), self._bound_max)
            value = b"".join(values)
        else:
            value = b"".join(v.encode() for v in self._values_for_encoding())
        return b"".join((self.tag, len_encode(len(value)), value))

    def _encode1st(self, state):
        state = super()._encode1st(state)
        if hasattr(self._value, NEXT_ATTR_NAME):
            self._value = []
        return state

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self.tag + len_encode(next(state_iter)))
        iterator = hasattr(self._value, NEXT_ATTR_NAME)
        if iterator:
            values_count = 0
            class_expected = self.spec.__class__
            values_for_encoding = self._values_for_encoding()
            self._value = []
            for v in values_for_encoding:
                if not isinstance(v, class_expected):
                    raise InvalidValueType((class_expected,))
                v.encode2nd(writer, state_iter)
                values_count += 1
            if not self._bound_min <= values_count <= self._bound_max:
                raise BoundsError(self._bound_min, values_count, self._bound_max)
        else:
            for v in self._values_for_encoding():
                v.encode2nd(writer, state_iter)

    def _encode_cer(self, writer):
        write_full(writer, self.tag + LENINDEF)
        iterator = hasattr(self._value, NEXT_ATTR_NAME)
        if iterator:
            class_expected = self.spec.__class__
            values_count = 0
            values_for_encoding = self._values_for_encoding()
            self._value = []
            for v in values_for_encoding:
                if not isinstance(v, class_expected):
                    raise InvalidValueType((class_expected,))
                v.encode_cer(writer)
                values_count += 1
            if not self._bound_min <= values_count <= self._bound_max:
                raise BoundsError(self._bound_min, values_count, self._bound_max)
        else:
            for v in self._values_for_encoding():
                v.encode_cer(writer)
        write_full(writer, EOC)

    def _decode(
            self,
            tlv,
            offset,
            decode_path,
            ctx,
            tag_only,
            evgen_mode,
            ordering_check=False,
    ):
        try:
            t, tlen, lv = tag_strip(tlv)
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if t != self.tag:
            raise TagMismatch(
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if tag_only:
            yield None
            return
        lenindef = False
        ctx_bered = ctx.get("bered", False)
        try:
            l, llen, v = len_decode(lv)
        except LenIndefForm as err:
            if not ctx_bered:
                raise err.__class__(
                    msg=err.msg,
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            l, llen, v = 0, 1, lv[1:]
            lenindef = True
        except DecodeError as err:
            raise err.__class__(
                msg=err.msg,
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if l > len(v):
            raise NotEnoughData(
                "encoded length is longer than data",
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if not lenindef:
            v, tail = v[:l], v[l:]
        vlen = 0
        sub_offset = offset + tlen + llen
        _value = []
        _value_count = 0
        ctx_allow_unordered_set = ctx.get("allow_unordered_set", False)
        value_prev = memoryview(v[:0])
        ber_encoded = False
        spec = self.spec
        while len(v) > 0:
            if lenindef and v[:EOC_LEN].tobytes() == EOC:
                break
            sub_decode_path = decode_path + (str(_value_count),)
            if evgen_mode:
                for _decode_path, value, v_tail in spec.decode_evgen(
                        v,
                        sub_offset,
                        leavemm=True,
                        decode_path=sub_decode_path,
                        ctx=ctx,
                        _ctx_immutable=False,
                ):
                    yield _decode_path, value, v_tail
            else:
                _, value, v_tail = next(spec.decode_evgen(
                    v,
                    sub_offset,
                    leavemm=True,
                    decode_path=sub_decode_path,
                    ctx=ctx,
                    _ctx_immutable=False,
                    _evgen_mode=False,
                ))
            value_len = value.fulllen
            if ordering_check:
                if value_prev.tobytes() > v[:value_len].tobytes():
                    if ctx_bered or ctx_allow_unordered_set:
                        ber_encoded = True
                    else:
                        raise DecodeError(
                            "unordered " + self.asn1_type_name,
                            klass=self.__class__,
                            decode_path=sub_decode_path,
                            offset=sub_offset,
                        )
                value_prev = v[:value_len]
            _value_count += 1
            if not evgen_mode:
                _value.append(value)
            sub_offset += value_len
            vlen += value_len
            v = v_tail
        if evgen_mode and not self._bound_min <= _value_count <= self._bound_max:
            raise DecodeError(
                msg=str(BoundsError(self._bound_min, _value_count, self._bound_max)),
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        try:
            obj = self.__class__(
                value=None if evgen_mode else _value,
                schema=spec,
                bounds=(self._bound_min, self._bound_max),
                impl=self.tag,
                expl=self._expl,
                default=self.default,
                optional=self.optional,
                _decoded=(offset, llen, vlen + (EOC_LEN if lenindef else 0)),
            )
        except BoundsError as err:
            raise DecodeError(
                msg=str(err),
                klass=self.__class__,
                decode_path=decode_path,
                offset=offset,
            )
        if lenindef:
            if v[:EOC_LEN].tobytes() != EOC:
                raise DecodeError(
                    "no EOC",
                    klass=self.__class__,
                    decode_path=decode_path,
                    offset=offset,
                )
            obj.lenindef = True
            tail = v[EOC_LEN:]
        obj.ber_encoded = ber_encoded
        yield decode_path, obj, tail

    def __repr__(self):
        return "%s[%s]" % (
            pp_console_row(next(self.pps())),
            ", ".join(repr(v) for v in self._value),
        )

    def pps(self, decode_path=()):
        yield _pp(
            obj=self,
            asn1_type_name=self.asn1_type_name,
            obj_name=self.__class__.__name__,
            decode_path=decode_path,
            optional=self.optional,
            default=self == self.default,
            impl=None if self.tag == self.tag_default else tag_decode(self.tag),
            expl=None if self._expl is None else tag_decode(self._expl),
            offset=self.offset,
            tlen=self.tlen,
            llen=self.llen,
            vlen=self.vlen,
            expl_offset=self.expl_offset if self.expled else None,
            expl_tlen=self.expl_tlen if self.expled else None,
            expl_llen=self.expl_llen if self.expled else None,
            expl_vlen=self.expl_vlen if self.expled else None,
            expl_lenindef=self.expl_lenindef,
            lenindef=self.lenindef,
            ber_encoded=self.ber_encoded,
            bered=self.bered,
        )
        for i, value in enumerate(self._value):
            yield value.pps(decode_path=decode_path + (str(i),))
        for pp in self.pps_lenindef(decode_path):
            yield pp


class SetOf(SequenceOf):
    """``SET OF`` sequence type

    Its usage is identical to :py:class:`pyderasn.SequenceOf`.
    """
    __slots__ = ()
    tag_default = tag_encode(form=TagFormConstructed, num=17)
    asn1_type_name = "SET OF"

    def _value_sanitize(self, value):
        value = super()._value_sanitize(value)
        if hasattr(value, NEXT_ATTR_NAME):
            raise ValueError(
                "SetOf does not support iterator values, as no sense in them"
            )
        return value

    def _encode(self):
        v = b"".join(sorted(v.encode() for v in self._values_for_encoding()))
        return b"".join((self.tag, len_encode(len(v)), v))

    def _encode2nd(self, writer, state_iter):
        write_full(writer, self.tag + len_encode(next(state_iter)))
        values = []
        for v in self._values_for_encoding():
            buf = BytesIO()
            v.encode2nd(buf.write, state_iter)
            values.append(buf.getvalue())
        values.sort()
        for v in values:
            write_full(writer, v)

    def _encode_cer(self, writer):
        write_full(writer, self.tag + LENINDEF)
        for v in sorted(encode_cer(v) for v in self._values_for_encoding()):
            write_full(writer, v)
        write_full(writer, EOC)

    def _decode(self, tlv, offset, decode_path, ctx, tag_only, evgen_mode):
        return super()._decode(
            tlv,
            offset,
            decode_path,
            ctx,
            tag_only,
            evgen_mode,
            ordering_check=True,
        )


def obj_by_path(pypath):  # pragma: no cover
    """Import object specified as string Python path

    Modules must be separated from classes/functions with ``:``.

    >>> obj_by_path("foo.bar:Baz")
    <class 'foo.bar.Baz'>
    >>> obj_by_path("foo.bar:Baz.boo")
    <classmethod 'foo.bar.Baz.boo'>
    """
    mod, objs = pypath.rsplit(":", 1)
    from importlib import import_module
    obj = import_module(mod)
    for obj_name in objs.split("."):
        obj = getattr(obj, obj_name)
    return obj


def generic_decoder():  # pragma: no cover
    # All of this below is a big hack with self references
    choice = PrimitiveTypes()
    choice.specs["SequenceOf"] = SequenceOf(schema=choice)
    choice.specs["SetOf"] = SetOf(schema=choice)
    for i in range(31):
        choice.specs["SequenceOf%d" % i] = SequenceOf(
            schema=choice,
            expl=tag_ctxc(i),
        )
    choice.specs["Any"] = Any()

    # Class name equals to type name, to omit it from output
    class SEQUENCEOF(SequenceOf):
        __slots__ = ()
        schema = choice

    def pprint_any(
            obj,
            oid_maps=(),
            with_colours=False,
            with_decode_path=False,
            decode_path_only=(),
            decode_path=(),
    ):
        def _pprint_pps(pps):
            for pp in pps:
                if hasattr(pp, "_fields"):
                    if (
                            decode_path_only != () and
                            pp.decode_path[:len(decode_path_only)] != decode_path_only
                    ):
                        continue
                    if pp.asn1_type_name == Choice.asn1_type_name:
                        continue
                    pp_kwargs = pp._asdict()
                    pp_kwargs["decode_path"] = pp.decode_path[:-1] + (">",)
                    pp = _pp(**pp_kwargs)
                    yield pp_console_row(
                        pp,
                        oid_maps=oid_maps,
                        with_offsets=True,
                        with_blob=False,
                        with_colours=with_colours,
                        with_decode_path=with_decode_path,
                        decode_path_len_decrease=len(decode_path_only),
                    )
                    for row in pp_console_blob(
                            pp,
                            decode_path_len_decrease=len(decode_path_only),
                    ):
                        yield row
                else:
                    for row in _pprint_pps(pp):
                        yield row
        return "\n".join(_pprint_pps(obj.pps(decode_path)))
    return SEQUENCEOF(), pprint_any


def ascii_visualize(ba):
    """Output only ASCII printable characters, like in hexdump -C

    Example output for given binary string (right part)::

        92 2b 39 20 65 91 e6 8e  95 93 1a 58 df 02 78 ea  |.+9 e......X..x.|
                                                           ^^^^^^^^^^^^^^^^
    """
    return "".join((chr(b) if 0x20 <= b <= 0x7E else ".") for b in ba)


def hexdump(raw):
    """Generate ``hexdump -C`` like output

    Rendered example::

        00000000  30 80 30 80 a0 80 02 01  02 00 00 02 14 54 a5 18  |0.0..........T..|
        00000010  69 ef 8b 3f 15 fd ea ad  bd 47 e0 94 81 6b 06 6a  |i..?.....G...k.j|

    Result of that function is a generator of lines, where each line is
    a list of columns::

        [
            [...],
            ["00000010 ", " 69", " ef", " 8b", " 3f", " 15", " fd", " ea", " ad ",
                          " bd", " 47", " e0", " 94", " 81", " 6b", " 06", " 6a ",
                          " |i..?.....G...k.j|"]
            [...],
        ]
    """
    hexed = hexenc(raw).upper()
    addr, cols = 0, ["%08x " % 0]
    for i in range(0, len(hexed), 2):
        if i != 0 and i // 2 % 8 == 0:
            cols[-1] += " "
        if i != 0 and i // 2 % 16 == 0:
            cols.append(" |%s|" % ascii_visualize(bytes(raw[addr:addr + 16])))
            yield cols
            addr += 16
            cols = ["%08x " % addr]
        cols.append(" " + hexed[i:i + 2])
    if len(cols) > 0:
        cols.append(" |%s|" % ascii_visualize(bytes(raw[addr:])))
        yield cols


def browse(raw, obj, oid_maps=()):
    """Interactive browser

    :param bytes raw: binary data you decoded
    :param obj: decoded :py:class:`pyderasn.Obj`
    :param oid_maps: list of ``str(OID) <-> human readable string`` dictionaries.
                     Its human readable form is printed when OID is met

    .. note:: `urwid <http://urwid.org/>`__ dependency required

    This browser is an interactive terminal application for browsing
    structures of your decoded ASN.1 objects. You can quit it with **q**
    key. It consists of three windows:

    :tree:
     View of ASN.1 elements hierarchy. You can navigate it using **Up**,
     **Down**, **PageUp**, **PageDown**, **Home**, **End** keys.
     **Left** key goes to constructed element above. **Plus**/**Minus**
     keys collapse/uncollapse constructed elements. **Space** toggles it
    :info:
     window with various information about element. You can scroll it
     with **h**/**l** (down, up) (**H**/**L** for triple speed) keys
    :hexdump:
     window with raw data hexdump and highlighted current element's
     contents. It automatically focuses on element's data. You can
     scroll it with **j**/**k** (down, up) (**J**/**K** for triple
     speed) keys. If element has explicit tag, then it also will be
     highlighted with different colour

    Window's header contains current decode path and progress bars with
    position in *info* and *hexdump* windows.

    If you press **d**, then current element will be saved in the
    current directory under its decode path name (adding ".0", ".1", etc
    suffix if such file already exists). **D** will save it with explicit tag.

    You can also invoke it with ``--browse`` command line argument.
    """
    from copy import deepcopy
    from os.path import exists as path_exists
    import urwid

    class TW(urwid.TreeWidget):
        def __init__(self, state, *args, **kwargs):
            self.state = state
            self.scrolled = {"info": False, "hexdump": False}
            super().__init__(*args, **kwargs)

        def _get_pp(self):
            pp = self.get_node().get_value()
            constructed = len(pp) > 1
            return (pp if hasattr(pp, "_fields") else pp[0]), constructed

        def _state_update(self):
            pp, _ = self._get_pp()
            self.state["decode_path"].set_text(
                ":".join(str(p) for p in pp.decode_path)
            )
            lines = deepcopy(self.state["hexed"])

            def attr_set(i, attr):
                line = lines[i // 16]
                idx = 1 + (i - 16 * (i // 16))
                line[idx] = (attr, line[idx])

            if pp.expl_offset is not None:
                for i in range(
                        pp.expl_offset,
                        pp.expl_offset + pp.expl_tlen + pp.expl_llen,
                ):
                    attr_set(i, "select-expl")
            for i in range(pp.offset, pp.offset + pp.tlen + pp.llen + pp.vlen):
                attr_set(i, "select-value")
            self.state["hexdump"]._set_body([urwid.Text(line) for line in lines])
            self.state["hexdump"].set_focus(pp.offset // 16)
            self.state["hexdump"].set_focus_valign("middle")
            self.state["hexdump_bar"].set_completion(
                (100 * pp.offset // 16) //
                len(self.state["hexdump"]._body.positions())
            )

            lines = [
                [("header", "Name: "), pp.obj_name],
                [("header", "Type: "), pp.asn1_type_name],
                [("header", "Offset: "), "%d (0x%x)" % (pp.offset, pp.offset)],
                [("header", "[TLV]len: "), "%d/%d/%d" % (
                    pp.tlen, pp.llen, pp.vlen,
                )],
                [("header", "TLVlen: "), "%d" % sum((
                    pp.tlen, pp.llen, pp.vlen,
                ))],
                [("header", "Slice: "), "[%d:%d]" % (
                    pp.offset, pp.offset + pp.tlen + pp.llen + pp.vlen,
                )],
            ]
            if pp.lenindef:
                lines.append([("warning", "LENINDEF")])
            if pp.ber_encoded:
                lines.append([("warning", "BER encoded")])
            if pp.bered:
                lines.append([("warning", "BERed")])
            if pp.expl is not None:
                lines.append([("header", "EXPLICIT")])
                klass, _, num = pp.expl
                lines.append(["  Tag: %s%d" % (TagClassReprs[klass], num)])
                if pp.expl_offset is not None:
                    lines.append(["  Offset: %d" % pp.expl_offset])
                    lines.append(["  [TLV]len: %d/%d/%d" % (
                        pp.expl_tlen, pp.expl_llen, pp.expl_vlen,
                    )])
                    lines.append(["  TLVlen: %d" % sum((
                        pp.expl_tlen, pp.expl_llen, pp.expl_vlen,
                    ))])
                    lines.append(["  Slice: [%d:%d]" % (
                        pp.expl_offset,
                        pp.expl_offset + pp.expl_tlen + pp.expl_llen + pp.expl_vlen,
                    )])
            if pp.impl is not None:
                klass, _, num = pp.impl
                lines.append([
                    ("header", "IMPLICIT: "), "%s%d" % (TagClassReprs[klass], num),
                ])
            if pp.optional:
                lines.append(["OPTIONAL"])
            if pp.default:
                lines.append(["DEFAULT"])
            if len(pp.decode_path) > 0:
                ent = pp.decode_path[-1]
                if isinstance(ent, DecodePathDefBy):
                    lines.append([""])
                    value = str(ent.defined_by)
                    oid_name = find_oid_name(
                        ent.defined_by.asn1_type_name, oid_maps, value,
                    )
                    lines.append([("header", "DEFINED BY: "), "%s" % (
                        value if oid_name is None
                        else "%s (%s)" % (oid_name, value)
                    )])
            lines.append([""])
            if pp.value is not None:
                lines.append([("header", "Value: "), pp.value])
                if (
                        len(oid_maps) > 0 and
                        pp.asn1_type_name == ObjectIdentifier.asn1_type_name
                ):
                    for oid_map in oid_maps:
                        oid_name = oid_map.get(pp.value)
                        if oid_name is not None:
                            lines.append([("header", "Human: "), oid_name])
                            break
                if pp.asn1_type_name == Integer.asn1_type_name:
                    lines.append([
                        ("header", "Decimal: "), "%d" % int(pp.obj),
                    ])
                    lines.append([
                        ("header", "Hexadecimal: "), colonize_hex(pp.obj.tohex()),
                    ])
            if pp.blob.__class__ == bytes:
                blob = hexenc(pp.blob).upper()
                for i in range(0, len(blob), 32):
                    lines.append([colonize_hex(blob[i:i + 32])])
            elif pp.blob.__class__ == tuple:
                lines.append([", ".join(pp.blob)])
            self.state["info"]._set_body([urwid.Text(line) for line in lines])
            self.state["info_bar"].set_completion(0)

        def selectable(self):
            if self.state["widget_current"] != self:
                self.state["widget_current"] = self
                self.scrolled["info"] = False
                self.scrolled["hexdump"] = False
                self._state_update()
            return super().selectable()

        def _get_display_text_without_offset(self):
            pp, constructed = self._get_pp()
            style = "constructed" if constructed else ""
            if len(pp.decode_path) == 0:
                return (style, pp.obj_name)
            if pp.asn1_type_name == "EOC":
                return ("eoc", "EOC")
            ent = pp.decode_path[-1]
            if isinstance(ent, DecodePathDefBy):
                value = str(ent.defined_by)
                oid_name = find_oid_name(
                    ent.defined_by.asn1_type_name, oid_maps, value,
                )
                return ("defby", "DEFBY:" + (
                    value if oid_name is None else oid_name
                ))
            return (style, ent)

        def get_display_text(self):
            pp, _ = self._get_pp()
            style, ent = self._get_display_text_without_offset()
            return [(style, ent), " [%d]" % pp.offset]

        def _scroll(self, what, step):
            self.state[what]._invalidate()
            pos = self.state[what].focus_position
            if not self.scrolled[what]:
                self.scrolled[what] = True
                pos -= 2
            pos = max(0, pos + step)
            pos = min(pos, len(self.state[what]._body.positions()) - 1)
            self.state[what].set_focus(pos)
            self.state[what].set_focus_valign("top")
            self.state[what + "_bar"].set_completion(
                (100 * pos) // len(self.state[what]._body.positions())
            )

        def keypress(self, size, key):
            if key == "q":
                raise urwid.ExitMainLoop()

            if key == " ":
                self.expanded = not self.expanded
                self.update_expanded_icon()
                return None

            hexdump_steps = {"j": 1, "k": -1, "J": 5, "K": -5}
            if key in hexdump_steps:
                self._scroll("hexdump", hexdump_steps[key])
                return None

            info_steps = {"h": 1, "l": -1, "H": 5, "L": -5}
            if key in info_steps:
                self._scroll("info", info_steps[key])
                return None

            if key in ("d", "D"):
                pp, _ = self._get_pp()
                dp = ":".join(str(p) for p in pp.decode_path)
                dp = dp.replace(" ", "_")
                if dp == "":
                    dp = "root"
                if key == "d" or pp.expl_offset is None:
                    data = self.state["raw"][pp.offset:(
                        pp.offset + pp.tlen + pp.llen + pp.vlen
                    )]
                else:
                    data = self.state["raw"][pp.expl_offset:(
                        pp.expl_offset + pp.expl_tlen + pp.expl_llen + pp.expl_vlen
                    )]
                ctr = 0

                def duplicate_path(dp, ctr):
                    if ctr == 0:
                        return dp
                    return "%s.%d" % (dp, ctr)

                while True:
                    if not path_exists(duplicate_path(dp, ctr)):
                        break
                    ctr += 1
                dp = duplicate_path(dp, ctr)
                with open(dp, "wb") as fd:
                    fd.write(data)
                self.state["decode_path"].set_text(
                    ("warning", "Saved to: " + dp)
                )
                return None
            return super().keypress(size, key)

    class PN(urwid.ParentNode):
        def __init__(self, state, value, *args, **kwargs):
            self.state = state
            if not hasattr(value, "_fields"):
                value = list(value)
            super().__init__(value, *args, **kwargs)

        def load_widget(self):
            return TW(self.state, self)

        def load_child_keys(self):
            value = self.get_value()
            if hasattr(value, "_fields"):
                return []
            return range(len(value[1:]))

        def load_child_node(self, key):
            return PN(
                self.state,
                self.get_value()[key + 1],
                parent=self,
                key=key,
                depth=self.get_depth() + 1,
            )

    class LabeledPG(urwid.ProgressBar):
        def __init__(self, label, *args, **kwargs):
            self.label = label
            super().__init__(*args, **kwargs)

        def get_text(self):
            return "%s: %s" % (self.label, super().get_text())

    WinHexdump = urwid.ListBox([urwid.Text("")])
    WinInfo = urwid.ListBox([urwid.Text("")])
    WinDecodePath = urwid.Text("", "center")
    WinInfoBar = LabeledPG("info", "pg-normal", "pg-complete")
    WinHexdumpBar = LabeledPG("hexdump", "pg-normal", "pg-complete")
    WinTree = urwid.TreeListBox(urwid.TreeWalker(PN(
        {
            "raw": raw,
            "hexed": list(hexdump(raw)),
            "widget_current": None,
            "info": WinInfo,
            "info_bar": WinInfoBar,
            "hexdump": WinHexdump,
            "hexdump_bar": WinHexdumpBar,
            "decode_path": WinDecodePath,
        },
        list(obj.pps()),
    )))
    help_text = " ".join((
        "q:quit",
        "space:(un)collapse",
        "(pg)up/down/home/end:nav",
        "jkJK:hexdump hlHL:info",
        "dD:dump",
    ))
    urwid.MainLoop(
        urwid.Frame(
            urwid.Columns([
                ("weight", 1, WinTree),
                ("weight", 2, urwid.Pile([
                    urwid.LineBox(WinInfo),
                    urwid.LineBox(WinHexdump),
                ])),
            ]),
            header=urwid.Columns([
                ("weight", 2, urwid.AttrWrap(WinDecodePath, "header")),
                ("weight", 1, WinInfoBar),
                ("weight", 1, WinHexdumpBar),
            ]),
            footer=urwid.AttrWrap(urwid.Text(help_text), "help")
        ),
        [
            ("header", "bold", ""),
            ("constructed", "bold", ""),
            ("help", "light magenta", ""),
            ("warning", "light red", ""),
            ("defby", "light red", ""),
            ("eoc", "dark red", ""),
            ("select-value", "light green", ""),
            ("select-expl", "light red", ""),
            ("pg-normal", "", "light blue"),
            ("pg-complete", "black", "yellow"),
        ],
    ).run()


def main():  # pragma: no cover
    import argparse
    parser = argparse.ArgumentParser(description="PyDERASN ASN.1 BER/CER/DER decoder")
    parser.add_argument(
        "--skip",
        type=int,
        default=0,
        help="Skip that number of bytes from the beginning",
    )
    parser.add_argument(
        "--oids",
        help="Python paths to dictionary with OIDs, comma separated",
    )
    parser.add_argument(
        "--schema",
        help="Python path to schema definition to use",
    )
    parser.add_argument(
        "--defines-by-path",
        help="Python path to decoder's defines_by_path",
    )
    parser.add_argument(
        "--nobered",
        action="store_true",
        help="Disallow BER encoding",
    )
    parser.add_argument(
        "--print-decode-path",
        action="store_true",
        help="Print decode paths",
    )
    parser.add_argument(
        "--decode-path-only",
        help="Print only specified decode path",
    )
    parser.add_argument(
        "--allow-expl-oob",
        action="store_true",
        help="Allow explicit tag out-of-bound",
    )
    parser.add_argument(
        "--evgen",
        action="store_true",
        help="Turn on event generation mode",
    )
    parser.add_argument(
        "--browse",
        action="store_true",
        help="Start ASN.1 browser",
    )
    parser.add_argument(
        "RAWFile",
        type=argparse.FileType("rb"),
        help="Path to BER/CER/DER file you want to decode",
    )
    args = parser.parse_args()
    try:
        raw = file_mmaped(args.RAWFile)[args.skip:]
    except:
        args.RAWFile.seek(args.skip)
        raw = memoryview(args.RAWFile.read())
        args.RAWFile.close()
    oid_maps = (
        [obj_by_path(_path) for _path in (args.oids or "").split(",")]
        if args.oids else ()
    )
    from functools import partial
    if args.schema:
        schema = obj_by_path(args.schema)
        pprinter = partial(pprint, big_blobs=True)
    else:
        schema, pprinter = generic_decoder()
    ctx = {
        "bered": not args.nobered,
        "allow_expl_oob": args.allow_expl_oob,
    }
    if args.defines_by_path is not None:
        ctx["defines_by_path"] = obj_by_path(args.defines_by_path)
    if args.browse:
        obj, _ = schema().decode(raw, ctx=ctx)
        browse(raw, obj, oid_maps)
        from sys import exit as sys_exit
        sys_exit(0)
    from os import environ
    pprinter = partial(
        pprinter,
        oid_maps=oid_maps,
        with_colours=environ.get("NO_COLOR") is None,
        with_decode_path=args.print_decode_path,
        decode_path_only=(
            () if args.decode_path_only is None else
            tuple(args.decode_path_only.split(":"))
        ),
    )
    if args.evgen:
        for decode_path, obj, tail in schema().decode_evgen(raw, ctx=ctx):
            print(pprinter(obj, decode_path=decode_path))
    else:
        obj, tail = schema().decode(raw, ctx=ctx)
        print(pprinter(obj))
    if tail != b"":
        print("\nTrailing data: %s" % hexenc(tail))


if __name__ == "__main__":
    from pyderasn import *
    main()
