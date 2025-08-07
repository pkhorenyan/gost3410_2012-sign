.. _performance:

Performance
===========

.. contents::

Performance is compared between ``pyderasn==6.1``, ``pyasn1==0.4.8`` and
``asn1crypto==1.3.0``. Decode CACert.org's CRL (2019-02-08 state, 8.72
MiB), encode it, pickle decoded structure and unpickle it. Machine is
Intel Core i5-6200U 2.3 GHz, 8 GB RAM, FreeBSD 12.0 amd64, Python 2.7.15
and Python 3.6.6 from native FreeBSD ports.

Code
----

pyasn1::

    from pyasn1.codec.der.decoder import decode as der_decoder
    from pyasn1.codec.der.encoder import encode as der_encoder
    from pyasn1_modules.rfc5280 import CertificateList
    with open("revoke.crl", "rb") as fd:
        raw = fd.read()
    start = time()
    crl, _ = der_decoder(raw, asn1Spec=CertificateList())
    print("decode", time() - start)
    del raw
    gc.collect()
    start = time()
    der_encoder(c)
    print("encode", time() - start)
    # pyasn1 objects are not picklable

asn1crypto::

    from asn1crypto.crl import CertificateList
    with open("revoke.crl", "rb") as fd:
        raw = fd.read()
    start = time()
    crl = CertificateList.load(raw)
    c.native  # full decoding and Python representation requires that
    print("decode", time() - start)
    del raw
    gc.collect()
    start = time()
    crl.dump(force=True)  # forced DER encoding
    print("encode", time() - start)
    start = time()
    raw = pickle.dumps(crl)
    print("dumps", time() - start)
    del crl
    gc.collect()
    print(len(raw))
    start = time()
    pickle.loads(raw)
    print("loads", time() - start)

pyderasn::

    from tests.test_crl import CertificateList
    with open("revoke.crl", "rb") as fd:
        raw = fd.read()
    start = time()
    crl = CertificateList().decod(raw)
    print("decode", time() - start)
    del raw
    gc.collect()
    start = time()
    crl.encode()
    print("encode", time() - start)
    start = time()
    raw = pickle.dumps(crl)
    print("dumps", time() - start)
    del crl
    gc.collect()
    print(len(raw))
    start = time()
    pickle.loads(raw)
    print("loads", time() - start)

Also there are `cythonized <https://cython.org/>`__ asn1crypto and
pyderasn versions, made using ``Cython==0.29.14``,
``FreeBSD clang version 6.0.1 (tags/RELEASE_601/final 335540) (based on
LLVM 6.0.1)``, ``CFLAGS=-O2`` and Python 3 mode.

DER
---

.. list-table::
   :header-rows: 1

   * - Library
     - Decode time, sec (Py36/Py27)
     - Encode time, sec (Py36/Py27)
     - Memory used, MiB (Py36/Py27)
   * - pyasn1
     - 1353 / 1400
     - 37.5 / 36.7
     - 1645 / 3296
   * - asn1crypto
     - 27.5 / 38
     - 25.7 / 28
     - 876 / 1742
   * - cython asn1crypto
     - 15.6 / N/A
     - 15.8 / N/A
     - 880 / N/A
   * - pyderasn
     - 33.2 / 33.4
     - 7.6 / 7.4
     - 560 / 516
   * - cython pyderasn
     - 23 / N/A
     - 5.9 / N/A
     - 561 / N/A

asn1crypto performs slightly better (with higher memory cost), but pay
attention that it contains **much** less data for all objects (like
offsets, sizes, etc) and it is not strict at all, passing possibly
invalid DER structures! Also there are plenty of other :ref:`features`
it lacks.

pickle
------

pyasn1 objects are not pickable.

.. list-table::
   :header-rows: 1

   * - Library
     - dumps time, sec (Py36/Py27)
     - loads time, sec (Py36/Py27)
     - Memory used, MiB (Py36/Py27)
     - Size, MiB (Py36/Py27)
   * - asn1crypto
     - 7.9 / 145
     - 8.3 / 91.4
     - 2474 / 4944
     - 174.8 / 373
   * - pyderasn
     - 82 / 244
     - 17 / 77.8
     - 3010 / 4372
     - 110.5 / 248.6
