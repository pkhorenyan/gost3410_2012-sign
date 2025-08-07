# coding: utf-8

from setuptools import setup


version = open("VERSION", "rb").read().strip().decode("ascii")

setup(
    name="pyderasn",
    version=version,
    description="Python ASN.1 DER/CER/BER codec with abstract structures",
    long_description=open("README", "rb").read().decode("utf-8"),
    author="Sergey Matveev",
    author_email="stargrave@stargrave.org",
    url="http://www.pyderasn.cypherpunks.ru/",
    license="LGPLv3",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Communications",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    py_modules=["pyderasn"],
    extras_require={
        "tz": ["python-dateutil~=2.7"],
    },
)
