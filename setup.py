##############################################################################
#
# Copyright (c) 2010-2015 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################

from setuptools import find_packages
from setuptools import setup


setup(
    name='AuthEncoding',
    version='5.0',
    url='https://github.com/zopefoundation/AuthEncoding',
    project_urls={
        'Sources': 'https://github.com/zopefoundation/AuthEncoding',
        'Issue Tracker': ('https://github.com/zopefoundation/'
                          'AuthEncoding/issues'),
    },
    license='ZPL 2.1',
    description="Framework for handling LDAP style password hashes.",
    author='Zope Foundation and Contributors',
    author_email='zope-dev@zope.org',
    long_description=(open('README.txt').read() + '\n' +
                      open('CHANGES.txt').read()),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    classifiers=[
        "Development Status :: 6 - Mature",
        "Environment :: Web Environment",
        "Framework :: Zope2",
        "Framework :: Zope",
        "Framework :: Zope :: 2",
        "Framework :: Zope :: 4",
        "Framework :: Zope :: 5",
        "License :: OSI Approved :: Zope Public License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: System :: Systems Administration ::"
        " Authentication/Directory :: LDAP",
    ],
    python_requires='>=3.7',
    extras_require={
        'test': [
            'pytest',
        ],
        'bcrypt': [
            'bcrypt',
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
