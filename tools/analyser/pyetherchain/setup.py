#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="pyetherchain",
    version="0.3.2",
    packages=["pyetherchain"],
    author="tintinweb",
    author_email="tintinweb@oststrom.com",
    description=(
        "A python interface to the ethereum blockchain explorer at www.etherchain.org"),
    license="GPLv2",
    keywords=["etherchain.org", "etherchain", "ethereum", "blockchain", "explorer", "api"],
    url="https://github.com/tintinweb/pyetherchain/",
    download_url="https://github.com/tintinweb/pyetherchain/tarball/v0.3.2",
    #python setup.py register -r https://testpypi.python.org/pypi
    #long_description=read("README.rst") if os.path.isfile("README.rst") else read("README.md"),
    install_requires=["ethereum_input_decoder", "requests"],
    package_data={
                  'pyetherchain': ['pyetherchain'],
                  },
    test_suite="nose.collector",
    tests_require=["nose"],
)
