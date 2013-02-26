# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Dirk Stöcker <trac@dstoecker.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

from email.Utils import parseaddr
from urllib import urlencode
import urllib2
import re
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_

class SpamBustedFilterStrategy(Component):
    """Spam filter using the SpamBusted (http://www.spambusted.com/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'spambusted_karma', '3',
        """By how many points a SpamBusted reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'spambusted_api_key', '',
        """API key used to report SPAM.""", doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, get_distribution('TracSpamFilter').version
    )

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self._check_preconditions(False):
            return
        try:
            resp = self._send(req, author, ip, False)
            if resp == "Yes":
                return -abs(self.karma_points), N_('SpamBusted says this is spam')
        except urllib2.URLError, e:
            self.log.warn('SpamBusted request failed (%s)', e)
        except IOError, e:
            self.log.warn("SpamBusted request failed: %s", e)

    def train(self, req, author, content, ip, spam=True):
        if not spam or not self._check_preconditions(True):
            return

        try:
            self._send(req, author, ip, True)
        except urllib2.URLError, e:
            self.log.warn('SpamBusted request failed (%s)', e)
        except IOError, e:
            self.log.warn("SpamBusted request failed: %s", e)

    # Internal methods

    def _check_preconditions(self, train):
        if self.karma_points == 0:
            return False

        if train and not self.api_key:
            return False

        return True

    def _send(self, req, author, ip, train):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None
        if author_name == "anonymous":
            author_name = None

        params = {'ip': ip}
        if author_name:
            params['username'] = author_name
        if author_email:
            params['email'] = author_email

        if train:
            if not author_name:
                return
            params['api'] = self.api_key
            url = 'http://www.spambusted.com/api.php?' + urlencode(params)
            urlreq = urllib2.Request(url, None, {'User-Agent' : self.user_agent})
        else:
            url = 'http://www.spambusted.com/api.php?' + urlencode(params)
            urlreq = urllib2.Request(url, None, {'User-Agent' : self.user_agent})

        resp = urllib2.urlopen(urlreq, None, 3)
        return resp.read()

