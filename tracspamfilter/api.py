# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2006 Edgewall Software
# Copyright (C) 2005-2006 Matthew Good <trac@matt-good.net>
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
#         Christopher Lenz <cmlenz@gmx.de>

from difflib import SequenceMatcher
import inspect
from StringIO import StringIO
import textwrap
import time

from trac.config import BoolOption, IntOption
from trac.core import *
from trac.db import DatabaseManager
from trac.env import IEnvironmentSetupParticipant
from trac.perm import IPermissionRequestor
from trac.util.html import escape, html, Markup
from trac.util.text import shorten_line
from trac.web import Request
from tracspamfilter.model import LogEntry, schema, schema_version

__all__ = ['RejectContent', 'IFilterStrategy', 'FilterSystem']


class RejectContent(TracError):
    """Exception raised when content is rejected by a filter."""


class IFilterStrategy(Interface):

    def test(req, author, content):
        """Test the given content submission.
        
        Should return a `(points, reason)` tuple to affect the score of the
        submission, where `points` is an integer, and `reason` is a brief
        description of why the score is being affected.
        
        If the filter strategy does not want (or is not able) to effectively
        test the submission, it should return `None`.
        """

    def train(req, author, content, spam=True):
        """Train the filter by reporting a false negative or positive.
        
        The spam keyword argument is `True` if the content should be considered
        spam (a false negative), and `False` if the content was legitimate (a
        false positive).
        """


class FilterSystem(Component):
    strategies = ExtensionPoint(IFilterStrategy)

    implements(IEnvironmentSetupParticipant, IPermissionRequestor)

    min_karma = IntOption('spam-filter', 'min_karma', '0',
        """The minimum score required for a submission to be allowed.""")

    logging_enabled = BoolOption('spam-filter', 'logging_enabled', 'true',
        """Whether all content submissions and spam filtering activity should
        be logged to the database.""")

    purge_age = IntOption('spam-filter', 'purge_age', '7',
        """The number of days after which log entries should be purged.""")

    trust_authenticated = BoolOption('spam-filter', 'trust_authenticated',
                                     'true',
        """Whether content submissions by authenticated users should be trusted
        without checking for potential spam or other abuse.""")

    # Public methods

    def test(self, req, author, changes):
        """Test a submission against the registered filter strategies.
        
        @param req: the request object
        @param author: the name of the logged in user, or 'anonymous' if the
            user is not logged in
        @param changes: a list of `(old_content, new_content)` tuples for every
            modified "field", where `old_content` may contain the previous
            version of that field (if available), and `new_content` contains
            the newly submitted content
        """
        if self.trust_authenticated:
            # Authenticated users are trusted
            if req.authname and req.authname != 'anonymous':
                return

        if not author:
            author = 'anonymous'
        content = self._combine_changes(changes)
        abbrev = shorten_line(content)
        self.log.debug('Testing content %r submitted by "%s"', abbrev, author)

        score = 0
        reasons = []
        for strategy in self.strategies:
            try:
                retval = strategy.test(req, author, content)
            except Exception, e:
                self.log.exception('Filter strategy raised exception: %s', e)
            else:
                if retval:
                    points, reason = retval
                    self.log.debug('Filter strategy %r gave submission %d '
                                   'karma points (reason: %r)', strategy,
                                   points, reason)
                    score += points
                    if reason:
                        reasons.append((strategy.__class__.__name__, points,
                                        reason))

        if self.logging_enabled:
            headers = '\n'.join(['%s: %s' % (k[5:].replace('_', '-').title(), v)
                                 for k, v in req.environ.items()
                                 if k.startswith('HTTP_')])
            LogEntry(self.env, time.time(), req.path_info, author,
                     req.authname and req.authname != 'anonymous',
                     req.remote_addr, headers, content, score < self.min_karma,
                     score, ['%s (%d): %s' % r for r in reasons]).insert()
            LogEntry.purge(self.env, self.purge_age)

        if score < self.min_karma:
            self.log.warn('Rejecting submission %r by "%s" (%r) because it '
                          'earned only %d karma points (%d are required) for '
                          'the following reason(s): %r', abbrev, author,
                          req.remote_addr, score, self.min_karma,
                          ['%s: (%s) %s' % r for r in reasons])
            msg = ', '.join([r[2] for r in reasons if r[1] < 0])
            if msg:
                msg = ' (%s)' % msg
            raise RejectContent('Submission rejected as potential spam%s' % msg)

    def train(self, req, log_id, spam=True):
        environ = {}
        for name, value in req.environ.items():
            if not name.startswith('HTTP_'):
                environ[name] = value

        entry = LogEntry.fetch(self.env, log_id)
        if entry:
            self.log.debug('Marking as %s: %r submitted by "%s"',
                           spam and 'spam' or 'ham',
                           shorten_line(entry.content),
                           entry.author)
            fakeenv = environ.copy()
            for header in entry.headers.splitlines():
                name, value = header.split(':', 1)
                if name == 'Cookie': # breaks SimpleCookie somehow
                    continue
                cgi_name = 'HTTP_%s' % name.strip().replace('-', '_').upper()
                fakeenv[cgi_name] = value.strip()
            fakeenv['REQUEST_METHOD'] = 'POST'
            fakeenv['PATH_INFO'] = entry.path
            fakeenv['wsgi.input'] = StringIO('')
            fakeenv['REMOTE_ADDR'] = entry.ipnr
            if entry.authenticated:
                fakeenv['REMOTE_USER'] = entry.author

            for strategy in self.strategies:
                strategy.train(Request(fakeenv, None),
                               entry.author or 'anonymous',
                               entry.content, spam=spam)

            entry.update(rejected=spam)

    # IEnvironmentSetupParticipant

    def environment_created(self):
        self.upgrade_environment(self.env.get_db_cnx())

    def environment_needs_upgrade(self, db):
        cursor = db.cursor()
        cursor.execute("SELECT value FROM system "
                       "WHERE name='spamfilter_version'")
        try:
            row = cursor.fetchone()
            if not row or int(row[0]) < schema_version:
                return True
        except:
            db.rollback()
            return True

    def upgrade_environment(self, db):
        cursor = db.cursor()
        try:
            cursor.execute("SELECT value FROM system "
                           "WHERE name='spamfilter_version'")
            row = cursor.fetchone()
            current_version = row and int(row[0]) or 0
        except:
            db.rollback()
            current_version = 0

        from tracspamfilter import upgrades
        for version in range(current_version + 1, schema_version + 1):
            for function in upgrades.version_map.get(version):
                self.log.info(textwrap.fill(inspect.getdoc(function)))
                function(self.env, db)
                self.log.info('Done.')

        if current_version == 0:
            cursor.execute("INSERT INTO system VALUES "
                           "('spamfilter_version',%s)", (schema_version,))
            self.log.info('Created SpamFilter tables')
        else:
            cursor.execute("UPDATE system SET value=%s WHERE "
                           "name='spamfilter_version'", (schema_version,))
            self.log.info('Upgraded SpamFilter tables from version %d to %d',
                          current_version, schema_version)

    # IPermissionRequestor

    def get_permission_actions(self):
        return ['SPAM_CONFIG', 'SPAM_MONITOR', 'SPAM_TRAIN',
                ('SPAM_ADMIN', ['SPAM_CONFIG', 'SPAM_MONITOR', 'SPAM_TRAIN'])]

    # Internal methods

    def _combine_changes(self, changes, sep='\n\n'):
        fields = []
        for old_content, new_content in changes:
            if old_content:
                new_content = self._get_added_lines(old_content, new_content)
            fields.append(new_content)
        return sep.join(fields)

    def _get_added_lines(self, old_content, new_content):
        buf = []
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        matcher = SequenceMatcher(None, old_lines, new_lines)
        for group in matcher.get_grouped_opcodes(0):
            for tag, i1, i2, j1, j2 in group:
                if tag in ('insert', 'replace'):
                    buf.append('\n'.join(new_lines[j1:j2]))

        return '\n'.join(buf)
