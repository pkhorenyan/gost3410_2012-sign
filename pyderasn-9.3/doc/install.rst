Install
=======

Preferable way is to :ref:`download <download>` tarball with the
signature from `official website <http://www.pyderasn.cypherpunks.ru/>`__::

    $ [fetch|wget] http://www.pyderasn.cypherpunks.ru/download/pyderasn-9.3.tar.zst
    $ [fetch|wget] http://www.pyderasn.cypherpunks.ru/download/pyderasn-9.3.tar.zst.sig
    $ gpg --verify pyderasn-9.3.tar.zst.sig pyderasn-9.3.tar.zst
    $ zstd -d < pyderasn-9.3.tar.zst | tar xf -
    $ cd pyderasn-9.3
    $ python setup.py install
    # or copy pyderasn.py (possibly termcolor.py) to your PYTHONPATH

* ``termcolor`` is an optional dependency used for output colourizing.
* ``urwid`` is an optional dependency used for :ref:`interactive browser <browser>`.
* ``dateutil`` is an optional dependency used for ``.totzdatetime()`` method.

You could use pip (**no** OpenPGP authentication is performed!) with PyPI::

    $ echo pyderasn==9.3 --hash=sha256:TO-BE-FILLED > requirements.txt
    $ pip install --requirement requirements.txt

You have to verify downloaded tarballs integrity and authenticity to be
sure that you retrieved trusted and untampered software. `GNU Privacy
Guard <https://www.gnupg.org/>`__ is used for that purpose.

For the very first time it is necessary to get signing public key and
import it. It is provided below, but you should check alternative
resources.

::

    pub   rsa2048/0x04A933D1BA20327A 2017-09-20
          2ED6 C846 3051 02DF 5B4E  0383 04A9 33D1 BA20 327A
    uid   PyDERASN releases <pyderasn@cypherpunks.ru>

    $ gpg --auto-key-locate dane --locate-keys pyderasn at cypherpunks dot ru
    $ gpg --auto-key-locate wkd --locate-keys pyderasn at cypherpunks dot ru

.. literalinclude:: ../PUBKEY.asc
