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

from datetime import datetime, timedelta

from trac.config import IntOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy
from tracspamfilter.model import LogEntry


class IPThrottleFilterStrategy(Component):
    """Spam filter strategy that throttles multiple subsequent submissions from
    the same IP address.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'ip_throttle_karma', '3',
        """By how many points exceeding the configured maximum number of posts
        per hour impacts the overall score.""")

    max_posts = IntOption('spam-filter', 'max_posts_by_ip', '10',
        """The maximum allowed number of submissions per hour form a single IP
        address. If this limit is exceeded, subsequent permissions get negative
        karma.""")

    # IFilterStrategy implementation

    def test(self, req, author, content):
        threshold = datetime.now() - timedelta(hours=1)
        num_posts = 0
        for entry in LogEntry.select(self.env, ipnr=req.remote_addr):
            if datetime.fromtimestamp(entry.time) < threshold:
                break
            num_posts += 1

        if num_posts > self.max_posts:
            return -abs(self.karma_points) * num_posts / self.max_posts, \
                   'Maximum number of posts per hour for this IP exceeded'

    def train(self, req, author, content, spam=True):
        pass
