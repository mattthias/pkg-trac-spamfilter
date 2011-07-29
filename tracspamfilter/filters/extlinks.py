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

import re

from trac.config import IntOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy
from tracspamfilter.model import LogEntry


class ExternalLinksFilterStrategy(Component):
    """Spam filter strategy that reduces the karma of a submission if the
    content contains too many links to external sites.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'extlinks_karma', '2',
        """By how many points too many external links in a submission impact
        the overall score.""")

    max_links = IntOption('spam-filter', 'max_external_links', '4',
        """The maximum number of external links allowed in a submission until
        that submission gets negative karma.""")

    _URL_RE = re.compile('https?://([^/]+)/?', re.IGNORECASE)

    # IFilterStrategy methods

    def test(self, req, author, content):
        num_ext = 0
        for host in self._URL_RE.findall(content):
            if host != req.get_header('Host'):
                num_ext += 1

        if num_ext > self.max_links:
            return -abs(self.karma_points) * num_ext / self.max_links, \
                   'Maximum number of external links per post exceeded'

    def train(self, req, author, content, spam=True):
        pass
