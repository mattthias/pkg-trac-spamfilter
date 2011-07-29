#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

from setuptools import setup, find_packages

PACKAGE = 'TracSpamFilter'
VERSION = '0.2.1'

setup(
    name = PACKAGE,
    version = VERSION,
    description = 'Plugin for spam filtering',
    author = "Edgewall Software",
    author_email = "info@edgewall.com",
    url = 'http://trac.edgewall.org/wiki/SpamFilter',
    download_url = 'http://trac.edgewall.org/wiki/SpamFilter',
    license = 'BSD',
    classifiers=[
        'Framework :: Trac',
        'License :: OSI Approved :: BSD License', 
    ],
    keywords='trac plugin',

    packages = find_packages(exclude=['*.tests*']),
    package_data = {'tracspamfilter': ['templates/*', 'htdocs/*']},
    extras_require = {
        'DNS': ['dnspython>=1.3.5'],
        'SpamBayes': ['spambayes'],
    },
    entry_points = """
        [trac.plugins]
        spamfilter = tracspamfilter.api
        spamfilter.admin = tracspamfilter.admin
        spamfilter.adapters = tracspamfilter.adapters
        spamfilter.akismet = tracspamfilter.filters.akismet
        spamfilter.bayes = tracspamfilter.filters.bayes[SpamBayes]
        spamfilter.extlinks = tracspamfilter.filters.extlinks
        spamfilter.ip_blacklist = tracspamfilter.filters.ip_blacklist[DNS]
        spamfilter.ip_throttle = tracspamfilter.filters.ip_throttle
        spamfilter.regex = tracspamfilter.filters.regex
        spamfilter.session = tracspamfilter.filters.session
    """,
    test_suite = 'tracspamfilter.tests.suite',
    zip_safe = True
)
