News
====

.. _release9.3:

9.3
---
* CommonString's ``.memoryview()`` raises ValueError now for
  friendliness with linters

.. _release9.2:

9.2
---
* ``keep_memoryview`` context option appeared, respected by OctetString
  and Any objects during DER decoding. If set, then their internal
  values will keep memoryview reference instead of full bytes copy
* Correspondingly OctetString and Any have ``.memoryview()`` method

.. _release9.1:

9.1
---
* ``.totzdatetime()`` appeared in UTCTime and GeneralizedTime,
  explicitly setting UTC timezone information.
  Optional ``dateutils.tz`` library is required for that

.. _release9.0:

9.0
---
* Drop Python 2.7 support. No ``six`` dependency anymore

.. _release8.4:

8.4
---
* Fix previous release's style breaking in ASN.1 browser

.. _release8.3:

8.3
---
* Append offsets to tree elements in ASN.1 browser for ease of navigation

.. _release8.2:

8.2
---
* Trivial documentation fixes

.. _release8.1:

8.1
---
* Workability under Microsoft Windows OS should be restored: it has
  different ``mmap`` constants and implementation, preventing
  ``pyderasn`` importing

.. _release8.0:

8.0
---
* **Incompatible** change: explicitly check that only naive datetime
  objects are used for UTCTime and GeneralizedTime, raise an error
  otherwise. Previously they silently ignored ``tzinfo``

.. _release7.7:

7.7
---
* Strictly check that tag's long encoded form does not contain leading zero
  (X.690 8.1.2.4.2 (c))
* Strictly check that tag's long form is used in expected way for small values
  (X.690 8.1.2.2)

.. _release7.6:

7.6
---
* Proper strict alphabet validation of VisibleString
* VisibleString and IA5String also have ``allowable_chars`` property
* Fixed TeletexString, T61String use ``iso-8859-1`` encoding (instead of
  ``ascii``), because they are 8-bit encodings

.. _release7.5:

7.5
---
* Also print full TLVlen in ASN.1 browser

.. _release7.4:

7.4
---

* Fix DEFINED BY pprinting when invoking as __main__ module
* Integer has ``tohex()`` for getting hexadecimal representation of its value
* ``hexdump()`` (``hexdump -C`` like output) and ``ascii_visualize()``
  (visualize ASCII printable characters, like in ``hexdump -C``) pretty
  printing functions appeared
* Experimental ASN.1 interactive terminal browser (``--browse`` and
  ``pyderasn.browse``).
  You will need `urwid package <http://urwid.org/>`__ to use it

.. _release7.3:

7.3
---

* SEQUENCE/SET fully performs default value existence validation in
  evgen mode, by the cost of DEFAULTed value full decoding. That should
  not be the problem, as DEFAULTs are relatively small in practice. Now
  evgen mode has the same DER validation strictness as an ordinary one

.. _release7.2:

7.2
---

* Restored workability of some command line options
* 2-pass DER encoding mode with very little memory footprint

.. _release7.1:

7.1
---

* README updating

.. _release7.0:

7.0
---
* Fixed invalid behaviour where SET OF allowed multiple objects with the
  same tag to be successfully decoded
* Fixed possibly invalid SET DER encoding where objects were not sorted
  by tag, but by encoded representation
* ``Any`` does not allow empty data value now. Now it checks if it has
  valid ASN.1 tag
* ``SetOf`` is not treated as ready, if no value was set and minimum
  bounds are greater than zero
* ``Any`` allows an ordinary ``Obj`` storing, without its forceful
  encoded representation storage. That is required for CER encoding
  mode, where we do not know in advance what encoding will be used
* ``ObjectIdentifier`` stores values as C unsigned long integer,
  forbidding storage of huge integers, that must not be a problem in
  practice
* Initial support for so called ``evgen_mode``: event generation mode,
  where no in-memory objects storing happens, giving ability to process
  ASN.1 data without fully parsing it first. ``python -m pyderasn`` has
  ``--evgen`` mode switcher
* Useful ``agg_octet_string`` that is able to streamingly decode string
  from events of ``evgen_mode``, allowing strings retrieving without
  copying them to memory first
* Initial experimental CER encoding mode, allowing streaming encoding of
  the data directly to some writeable object
* Ability to use mmap-ed memoryviews to skip files loading to memory
* Ability to use memoryview as an input for \*Strings. If they are
  mmap-ed, then you can encode any quantities of data streamingly
  without copying to memory

.. _release6.3:

6.3
---
* Fixed workability under Python 3.5. Previously only 2.7 and 3.6
  versions were tested

.. _release6.2:

6.2
---
* Python ``int()``'s accepts even more various non-decimal characters
  than expected. Make validation fully strict in UTCTime and
  GeneralizedTime, without relying on ``int()``

.. _release6.1:

6.1
---
* UTCTime and GeneralizedTime allowed values to have plus sign in them,
  passing ``int()`` check successfully. Prohibit that incorrect behaviour
* UTCTime and GeneralizedTime BER decoding support
* Faster UTCTime and GeneralizedTime decoding, and slightly better
  overall performance
* Workability under Cython
* Explicitly Check that all ObjectIdentifier arcs are non-negative

.. _release6.0:

6.0
---
* ``.copy()`` method removed: ``copy.copy()`` is preferred way to copy
  objects now
* Copies made previously with ``.copy()`` lacked ``.defined`` field,
  now they are not
* All objects are friendly to ``pickle`` libraries
* PrintableString has ``allow_asterisk`` and ``allow_ampersand``
  properties
* ``.hexencode()``, ``.hexdecode()`` and ``.hexdecod()`` methods
  appeared, working with hexadecimal encoded data

.. _release5.6:

5.6
---
* Convenient ``.decod()`` method, that raises if tail is not empty
* Control characters (like newlines) of text fields in pprinted output
  are escaped
* Ability to allow asterisk and ampersand characters
  (``allow_asterisk``, ``allow_ampersand`` kwargs) in PrintableString,
  that unfortunately could be met in X.509 certificates

.. _release5.5:

5.5
---
* PEP-396 compatible module's ``__version__``

.. _release5.4:

5.4
---
* Do not shadow underlying DecodeError during decoding of optional
  sequence's field

.. _release5.3:

5.3
---
* Forbid any later GNU GPL version autousage (project's licence now is
  GNU LGPLv3 only)
* Fix ``defines_by_path`` context option usage example

.. _release5.2:

5.2
---
* Fix fallbacked ``colored()`` function workability,
  if no ``termcolor`` is installed

.. _release5.1:

5.1
---
* Fix empty ``--oids`` workability

.. _release5.0:

5.0
---
* Ability to specify multiple OID mappings for pprinted output
  (``oids`` keyword argument is renamed to ``oid_maps``)

.. _release4.9:

4.9
---
* Minor decode speed improvements
* Much faster UTCTime/GeneralizedTime decoders
* Stricter UTCTime/GeneralizedTime DER encoding check: trailing zeroes
  are forbidden
* Valid DER encoding of GeneralizedTime with microseconds: no trailing
  zeroes appended

.. _release4.7:

4.7
---
* ObjectIdentifier has ``ber_encoded`` set to True, if non-normalized
  arc encoding is met
* Preserve BER-related attributes during ``copy()``

.. _release4.6:

4.6
---
* Added `COMPLI <https://github.com/YuryStrozhevsky/asn1-test-suite>`__
  ASN.1:2008 test suite. PyDERASN passes it (except for REAL values),
  but it is more strict sometimes and aimed to be compliant with X.690-201508
* Check for arc values normalization in ObjectIdentifier.
  Forbid non-normalized in DER encoding

.. _release4.5:

4.5
---
* ``ctx`` parameter can be safely used in .decode() and won't be muted
* PP nametuple contains reference to the ASN1Obj itself
* ``colonize_hex`` function useful for pretty printing
* Integer values are also pretty printed in hexadecimal form

.. _release4.4:

4.4
---
* All errors are inherited from ASN1Error class
* NumericString/PrintableString has ``allowable_chars`` property holding
  all allowed characters

.. _release4.3:

4.3
---
* Fix NumericString: space is allowed character
* Strict PrintableString sanitizing

.. _release4.2:

4.2
---
* Removed ``lenindef``, ``ber_encoded`` attributes from the Choice --
  they must be taken from underlying value, as Choice does not have its
  own encoding
* Do not yield extra EOC PP for Any, having indefinite length encoding
  and containing autodecoded DEFINED BY value

.. _release4.1:

4.1
---
* ``bered`` attribute, meaning if object has BER-specific encoding, is
  renamed to ``ber_encoded``
* ``bered`` attribute is replace with property showing if any of
  underlying values are BER-encoded. If value has length indefinite
  encoded explicit tag, value, if value contains BER-related encoding,
  or if it contains other objects that are ``bered``, then it is ``bered``

.. _release4.0:

4.0
---
* Default value is checked also for Sets, not for Sequences only
* **Incompatible** change: defaulted values in Sequence/Set are always
  strictly checked, unless ``allow_default_values`` context option is
  set. ``strict_default_existence`` option disappeared
* Strict Set/Set Of's values ordering check

.. _release3.14:

3.14
----
* Additional encoding validness check: explicit tag must contain exactly
  one object inside. Throw DecodeError otherwise
* ``allow_expl_oob`` context and command-line options allow skipping of
  that check

.. _release3.13:

3.13
----
* DecodeError's decode paths are separated with ``:``, instead of ``.``,
  because of colliding with dots in OIDs
* Ability to print element decode paths with ``--print-decode-path``
  command line option (and corresponding keyword argument)
* Ability to print tree's branch specified with ``--decode-path-only``

.. _release3.12:

3.12
----
* Fix possible uncaught TypeError in Py2 with zero bytes inside the value
* Fix SequenceOf/SetOf raising BoundsError instead of DecodeError

.. _release3.11:

3.11
----
* Fix uncaught UTCTime/GeneralizedTime decode error when dealing with
  non ASCII-encoded values

.. _release3.10:

3.10
----
* Fix long-standing bug with explicitly tagged objects inside the
  Choice. If Choice had explicitly tagged value, then its ``.tlvlen``
  reports the size without taking value's explicit tag in advance
* Add ``.fulllen`` and ``.fulloffset`` properties for all objects

.. _release3.9:

3.9
---
* SEQUENCE's values are printed with field's name. Previously there was
  the following output::

    AlgorithmIdentifier SEQUENCE[OBJECT IDENTIFIER 1.3.14.3.2.26, [UNIV 5] ANY 0500 OPTIONAL]

  now it is::

    AlgorithmIdentifier SEQUENCE[algorithm: OBJECT IDENTIFIER 1.3.14.3.2.26; parameters: [UNIV 5] ANY 0500 OPTIONAL]
* Fixed EOC (Unicode character) repr printing issues under Python2

.. _release3.8:

3.8
---
BER's EOC is explicitly shown during pprinting. Following notation::

      15-2 [0,0,1576]-4  . content: [0] EXPLICIT [UNIV 16] ANY

is replaced with::

      15-2∞ [0,0,1576]∞  . content: [0] EXPLICIT [UNIV 16] ANY
    [...]
    1587    [1,1,   0]   . content:  BER EOC
    1589    [1,1,   0]   . content: EXPLICIT BER EOC

.. _release3.7:

3.7
---
* BER decoding support
* BitString's ''H notation support
* ``termcolor`` package is included in the tarball

.. _release3.6:

3.6
---
* Ability to set values during Sequence initialization

.. _release3.5:

3.5
---
* Fix TagMismatch exception completeness during Choice and Set decoding.
  Previously we will loose offset and decode_path information about
  concrete TagMismatched entity

.. _release3.4:

3.4
---
* Strict NumericString's value sanitation
* Invalid encoding in string types will raise ``DecodeError`` exception,
  instead of ``Unicode*Error``
* Fixed DecodePathDefBy workability with Python 2.x

.. _release3.3:

3.3
---
* Fix nasty BitString decoding bug: it could fail when data follows
  encoded BitString value. There weren't any problems when BitString is
  at the end of Sequence

.. _release3.2:

3.2
---
* Slightly corrected colours, now visible on white background

.. _release3.1:

3.1
---
* Fix bug related to DecodeError showing with DecodePathDefBy entities
* Respect ``NO_COLOR`` environment variable

.. _release3.0:

3.0
---
* :py:func:`pyderasn.decode_path_defby` is replaced with
  :py:class:`pyderasn.DecodePathDefBy`
* Ability to turn colourized terminal output by calling
  ``pprint(..., with_colours=True)``. You will need
  `termcolor package <https://pypi.org/project/termcolor/>`__

.. _release2.1:

2.1
---
* Fixed invalid offset calculation when dealing with DEFINED BY objects
  having explicit tags

.. _release2.0:

2.0
---
* BIT STRINGs can also be :ref:`DEFINED BY <definedby>`
* Decoding process can be governed with optional :ref:`ctx <ctx>`
  keyword argument to ``decode()`` method
* :ref:`defines_by_path <defines_by_path_ctx>` option is now
  :ref:`decode context <ctx>` option, not a keyword argument
* Ability to do ``strict validation``
  of defaulted values met in sequence, raising an exception

.. _release1.6:

1.6
---
Ability to skip specified number of bytes (``--skip``) in command line
utility.

.. _release1.5:

1.5
---
* Generic decoder's schema and pretty printer
  (:py:func:`pyderasn.generic_decoder`) can be used in libraries
* Ability to specify :ref:`defines_by_path <defines_by_path_ctx>`
  during command line invocation

.. _release1.4:

1.4
---
Ability to automatically decode :ref:`DEFINED BY <definedby>` fields
inside SEQUENCEs.

.. _release1.3:

1.3
---
Removed ``__lt__``/``__eq__`` from base class, as pylint likes it.

.. _release1.2:

1.2
---
Full rich comparison operators added.


.. _release1.1:

1.1
---
Trivial README addition.

.. _release1.0:

1.0
---
Initial release.
