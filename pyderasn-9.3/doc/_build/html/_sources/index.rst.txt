================================================================
PyDERASN -- strict and fast ASN.1 DER/CER/BER library for Python
================================================================

..

    I'm going to build my own ASN.1 library with slots and blobs!
    (C) PyDERASN's author

`ASN.1 <https://en.wikipedia.org/wiki/ASN.1>`__ (Abstract Syntax
Notation One) is a standard for abstract data serialization. PyDERASN is
yet another library for dealing with ASN.1 structures, decoding them in
`BER/CER/DER <https://en.wikipedia.org/wiki/X.690>`__ formats and
encoding to either DER (Distinguished Encoding Rules) or CER (Canonical
Encoding Rules). Although ASN.1 is written more than 30 years ago by wise
Ancients (taken from ``pyasn1``'s README), it is still often can be seen
anywhere in our life.

PyDERASN is `free software <https://www.gnu.org/philosophy/free-sw.html>`__,
licenced under `GNU LGPLv3 <https://www.gnu.org/licenses/lgpl-3.0.html>`__.

.. toctree::
   :maxdepth: 1

   features
   performance
   limitations
   examples
   reference
   news
   install
   download
   thanks
   feedback

There are articles about its history and usage:

* `Как я написал ASN.1 библиотеку с slots and blobs <https://m.habr.com/ru/post/444272/>`__ (on russian)
* `Как я добавил big-data поддержку <https://m.habr.com/ru/post/498014/>`__ (on russian)

.. figure:: pprinting.png
   :alt: Pretty printing example output

   An example of pretty printed X.509 certificate with automatically
   parsed DEFINED BY fields.

.. figure:: browser.png
   :alt: ASN.1 browser example

   An example of browser running.
