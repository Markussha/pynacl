#!/usr/bin/env python
from setuptools import setup

__about__ = {}

with open("nacl/__about__.py") as fp:
    exec(fp, None, __about__)


try:
    import nacl.nacl
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [nacl.nacl.ffi.verifier.get_extension()]


setup(
    name=__about__["__title__"],
    version=__about__["__version__"],

    description=__about__["__summary__"],
    long_description=open("README.rst").read(),
    url=__about__["__uri__"],
    license=__about__["__license__"],

    author=__about__["__author__"],
    author_email=__about__["__email__"],

    install_requires=[
        "cffi",
    ],

    packages=[
        "nacl",
    ],

    ext_package="nacl",
    ext_modules=ext_modules,

    zip_safe=False,
)