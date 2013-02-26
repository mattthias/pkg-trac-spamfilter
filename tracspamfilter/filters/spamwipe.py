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
import string
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from trac.mimeview.api import is_binary
from tracspamfilter.api import IFilterStrategy, N_

class SpamWipeFilterStrategy(Component):
    """Spam filter using the SpamWipet service (http://www.spamwipe.com/)."""
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'spamwipe_karma', '5',
        """By how many points an SpamWipe reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'spamwipe_api_key', '',
        """API key required to use the SpamWipe API.""", doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, get_distribution('TracSpamFilter').version
    )

    api_url = "http://api.spamwipe.com/1.0/comments/"

    def __init__(self):
        self.verified_key = None

    # IFilterStrategy implementation

    def is_external(self):
        return True
            
    def test(self, req, author, content, ip):
        if not self._check_preconditions(req, author, content):
            return

        try:
            url = '%sclassify' % (self.api_url)
            #self.log.debug('Checking content with SpamWipe service at %s', url)
            resp = self._post(url, req, author, content, ip)
            if string.find(resp, "<item>false</item>") >= 0:
                #self.log.debug('SpamWipe says content is ham')
                return abs(self.karma_points), N_('SpamWipe says content is ham')
            elif string.find(resp, "<item>true</item>") >= 0:
                #self.log.debug('SpamWipe says content is spam')
                return -abs(self.karma_points), N_('SpamWipe says content is spam')

        except urllib2.URLError, e:
            self.log.warn('SpamWipe request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        if not self._check_preconditions(req, author, content):
            return

        try:
            which = spam and 'spam' or 'ham'
            url = '%smarkas-%s' % (self.api_url, which)
            self.log.debug('Submitting %s to SpamWipe service at %s', which, url)
            self._post(url, req, author, content, ip)

        except urllib2.URLError, e:
            self.log.warn('SpamWipe request failed (%s)', e)

    # Internal methods

    def _check_preconditions(self, req, author, content):
        if self.karma_points == 0:
            return False

        if not self.api_key:
            self.log.debug('SpamWipe API key is missing')
            return False

        if is_binary(content):
            self.log.debug('Content is binary, SpamWipe content check skipped')
            return False

        try:
            if not self.verify_key(req):
                self.log.warning('SpamWipe API key is invalid')
                return False
            return True
        except urllib2.URLError, e:
            self.log.warn('SpamWipe request failed (%s)', e)

    def verify_key(self, req, api_key=None):
        if api_key is None:
            api_key = self.api_key

        if api_key != self.verified_key:
            self.log.debug('Verifying SpamWipe API key')
            params = {'site': req.base_url, 'key': api_key}
            req = urllib2.Request('%sverify-key' % self.api_url,
                                  urlencode(params),
                                  {'User-Agent' : self.user_agent})
            resp = urllib2.urlopen(req).read()
            if string.find(resp, "<item>valid</item>") >= 0:
                self.log.debug('SpamWipe API key is valid')
                self.verified = True
                self.verified_key = api_key

        return self.verified_key is not None

    def _post(self, url, req, author, content, ip):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None

        if not author_email:
            author_email = "invalid@invalid"

        params = {'site_ip': req.base_url, 'ip': ip,
                  'client_ua': req.get_header('User-Agent'),
                  'client_referer': req.get_header('Referer') or 'unknown',
                  'name': author_name,
                  'type': 'trac',
                  'email': author_email,
                  'comment': content.encode('utf-8'),
                  'HTTP_X_API_KEY': self.api_key}
        urlreq = urllib2.Request(url, urlencode(params),
                              {'User-Agent' : self.user_agent})

        resp = urllib2.urlopen(urlreq)
        return resp.read()
