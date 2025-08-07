.. _features:

Features
========

* BER/CER/DER decoding, strict DER validation, DER/CER encoding
* Basic ASN.1 data types (X.208): BOOLEAN, INTEGER, BIT STRING, OCTET
  STRING, NULL, OBJECT IDENTIFIER, ENUMERATED, all strings, UTCTime,
  GeneralizedTime, CHOICE, ANY, SEQUENCE (OF), SET (OF)
* Size :ref:`constraints <bounds>` checking
* Working with sequences as high level data objects with ability to
  (un)marshall them
* Python 3.5+ compatibility (2.7 dropped in version 9.0)
* Aimed to be complaint with `X.690-201508 <https://www.itu.int/rec/T-REC-X.690-201508-I/en>`__
* Streaming decoding and encoding capabilities, allowing working with
  very small memory footprint

Why yet another library? `pyasn1 <http://snmplabs.com/pyasn1/>`__
had all of this a long time ago. PyDERASN resembles it in many ways. In
practice it should be relatively easy to convert ``pyasn1``'s code to
``pyderasn``'s one.
Also there is `asn1crypto <https://github.com/wbond/asn1crypto>`__.

* Small, simple and trying to be reviewable code. Just a single file
* Ability to know :ref:`exact decoded <decoding>` objects offsets and
  lengths inside the binary
* Automatic decoding of :ref:`DEFINED BY <definedby>` fields
* Ability to know exact decoded field presence, emptiness: for example
  ``SEQUENCE`` can lack ``OPTIONAL SEQUENCE OF`` field, but also can
  have it with no elements inside
* **Strict** DER-encoding checks. If whole input binary is parsed, then
  it must be completely valid DER-encoded structure
* Ability to allow BER-encoded data with knowing if any of specified
  field has either DER or BER encoding (or possibly indefinite-length
  encoding). For example
  `CMS <https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax>`__
  structures allow BER encoding for the whole message, except for
  ``SignedAttributes`` -- you can easily verify your CMS satisfies that
  requirement
* Ability to use mmap-ed files, memoryviews, iterators, 2-pass DER
  encoding mode and CER encoder dealing with the writer, giving ability
  to create huge ASN.1 encoded files with very little memory footprint
* Ability to decode files in event generation mode, without the need to
  keep all the data and decoded structures (that takes huge quantity of
  memory in all known ASN.1 libraries) in the memory
* ``__slots__``, ``copy.copy()`` friendliness
* Workability with ``pickle``
* `Cython <https://cython.org/>`__ compatibility
* Extensive and comprehensive
  `hypothesis <https://hypothesis.readthedocs.io/en/master/>`__
  driven tests coverage. It also has been fuzzed with
  `python-afl <http://jwilk.net/software/python-afl>`__
* Some kind of strong typing: SEQUENCEs require the exact **type** of
  settable values, even when they are inherited (assigning ``Integer``
  to the field with the type ``CMSVersion(Integer)`` is not allowed)
* However they do not require exact tags matching: IMPLICIT/EXPLICIT
  tags will be set automatically in the given sequence (assigning of
  ``CMSVersion()`` object to the field ``CMSVersion(expl=...)`` will
  automatically set required tags)
* Descriptive errors, like ``pyderasn.DecodeError: UTCTime
  (tbsCertificate:validity:notAfter:utcTime) (at 328) invalid UTCTime format``
* Could be significantly :ref:`faster <performance>` and have lower memory usage
* :ref:`Pretty printer <pprinting>` and
  :ref:`command-line decoder <cmdline>`, that could
  conveniently replace utilities like either ``dumpasn1`` or
  ``openssl asn1parse``

  .. figure:: pprinting.png
     :alt: Pretty printing example output

     An example of pretty printed X.509 certificate with automatically
     parsed DEFINED BY fields.
* :ref:`ASN.1 browser <browser>`

  .. figure:: browser.png
     :alt: ASN.1 browser example

     An example of browser running.
