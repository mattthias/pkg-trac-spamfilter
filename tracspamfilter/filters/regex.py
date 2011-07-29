# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2006 Edgewall Software
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2006 Christopher Lenz <cmlenz@gmx.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.
#
# Author: Matthew Good <trac@matt-good.net>

import re

from trac.config import IntOption
from trac.core import *
from trac.wiki.api import IWikiChangeListener
from trac.wiki.model import WikiPage
from tracspamfilter.api import IFilterStrategy


class RegexFilterStrategy(Component):
    implements(IFilterStrategy, IWikiChangeListener)

    karma_points = IntOption('spam-filter', 'regex_karma', '5',
        """By how many points a match with a pattern on the BadContent page
        impacts the overall karma of a submission.""")

    def __init__(self):
        self.patterns = []
        page = WikiPage(self.env, 'BadContent')
        if page.exists:
            self._load_patterns(page)

    # IFilterStrategy implementation

    def test(self, req, author, content):
        points = 0
        for pattern in self.patterns:
            match = pattern.search(content)
            if match:
                self.log.debug('Pattern %r found in submission',
                               pattern.pattern)
                points -= abs(self.karma_points)
        if points != 0:
            return points, 'Content contained blacklisted patterns'

    def train(self, req, author, content, spam=True):
        pass

    # IWikiChangeListener implementation

    def wiki_page_changed(self, page, *args):
        if page.name == 'BadContent':
            self._load_patterns(page)
    wiki_page_added = wiki_page_changed
    wiki_page_version_deleted = wiki_page_changed

    def wiki_page_deleted(self, page):
        if page.name == 'BadContent':
            self.patterns = []

    # Internal methods

    def _load_patterns(self, page):
        if '{{{' in page.text and '}}}' in page.text:
            lines = page.text.split('{{{', 1)[1].split('}}}', 1)[0].splitlines()
            self.patterns = [re.compile(p.strip()) for p in lines if p.strip()]
            self.log.info('Loaded %s patterns from BadContent',
                          len(self.patterns))
        else:
            self.log.warning('BadContent page does not contain any patterns')
            self.patterns = []
