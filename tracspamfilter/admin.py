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

import os
import urllib2

from pkg_resources import require, resource_filename, ResolutionError

from trac import __version__ as VERSION
from trac.core import *
from trac.util import format_datetime, pretty_timedelta, shorten_line, sorted
from trac.web import Request, HTTPNotFound
from trac.web.chrome import add_link, add_stylesheet, ITemplateProvider
from tracspamfilter.api import FilterSystem
from tracspamfilter.model import LogEntry
from tracspamfilter.filters.akismet import AkismetFilterStrategy
try:
    from tracspamfilter.filters.bayes import BayesianFilterStrategy
except ImportError: # SpamBayes not installed
    BayesianFilterStrategy = None

try: # Trac 0.11
    from trac.admin import IAdminPanelProvider

except ImportError:
    IAdminPanelProvider = None

    try: # Trac 0.10 with WebAdmin plugin
        require("TracWebAdmin")
        from webadmin.web_ui import IAdminPageProvider
    except (ResolutionError, ImportError):
        IAdminPageProvider = None


class SpamFilterAdminPageProvider(Component):
    """Web administration panel for configuring and monitoring the spam
    filtering system.
    """

    implements(ITemplateProvider)
    if IAdminPanelProvider:
        implements(IAdminPanelProvider)
    elif IAdminPageProvider:
        implements(IAdminPageProvider)

    MAX_PER_PAGE = 15

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', 'Spam Filtering', 'config', 'Configuration')
        if req.perm.has_permission('SPAM_MONITOR'):
            yield ('spamfilter', 'Spam Filtering', 'monitor', 'Monitoring')

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'config':
            if req.method == 'POST':
                if self._process_config_panel(req):
                    req.redirect(req.href.admin(cat, page))
            data = self._render_config_panel(req, cat, page)
        else:
            if req.method == 'POST':
                if self._process_monitoring_panel(req):
                    req.redirect(req.href.admin(cat, page,
                                                page=req.args.get('page')))
            if path_info:
                data = self._render_monitoring_entry(req, cat, page, path_info)
                page = 'entry'
            else:
                data = self._render_monitoring_panel(req, cat, page)

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_spam%s.html' % page, data

    # IAdminPageProvider methods

    get_admin_pages = get_admin_panels

    def process_admin_request(self, req, cat, page, path_info):
        template, data = self.render_admin_panel(req, cat, page, path_info)

        # Kludges for ClearSilver
        if 'entries' in data:
            for idx, entry in enumerate(data['entries']):
                data['entries'][idx] = _entry_to_hdf(req, entry)
        elif 'entry' in data:
            data['entry'] = _entry_to_hdf(req, data['entry'])

        req.hdf['admin.spamfilter'] = data
        return template.replace('.html', '.cs'), None

    # ITemplateProvider

    def get_htdocs_dirs(self):
        """Return the absolute path of a directory containing additional
        static resources (such as images, style sheets, etc).
        """
        return [('spamfilter', resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        """Return the absolute path of the directory containing the provided
        ClearSilver templates.
        """
        return [resource_filename(__name__, 'templates')]

    # Internal methods

    def _render_config_panel(self, req, cat, page):
        req.perm.assert_permission('SPAM_CONFIG')
        filtersys = FilterSystem(self.env)

        strategies = []
        for strategy in filtersys.strategies:
            info = {'name': strategy.__class__.__name__,
                    'karma_points': strategy.karma_points,
                    'karma_help': strategy.__class__.karma_points.__doc__}
            strategies.append(info)

        return {
            'strategies': sorted(strategies, key=lambda x: x['name']),
            'min_karma': filtersys.min_karma,
            'logging_enabled': filtersys.logging_enabled,
            'purge_age': filtersys.purge_age
        }

    def _process_config_panel(self, req):
        req.perm.assert_permission('SPAM_CONFIG')

        try:
            min_karma = int(req.args.get('min_karma'))
            self.config.set('spam-filter', 'min_karma', min_karma)
        except ValueError:
            pass

        for strategy in FilterSystem(self.env).strategies:
            option = strategy.__class__.karma_points
            points = req.args.get(strategy.__class__.__name__ +
                                  '_karmapoints')
            if points is not None:
                self.config.set(option.section, option.name, points)

        logging_enabled = 'logging_enabled' in req.args
        self.config.set('spam-filter', 'logging_enabled',
                        str(logging_enabled).lower())

        if logging_enabled:
            try:
                purge_age = int(req.args.get('purge_age'))
                self.config.set('spam-filter', 'purge_age', purge_age)
            except ValueError:
                pass

        self.config.save()
        return True

    def _render_monitoring_panel(self, req, cat, page):
        req.perm.assert_permission('SPAM_MONITOR')

        try:
            pagenum = int(req.args.get('page', 1)) - 1
        except ValueError:
            pagenum = 1

        total = LogEntry.count(self.env)
        offset = pagenum * self.MAX_PER_PAGE
        entries = list(LogEntry.select(self.env, limit=self.MAX_PER_PAGE,
                                       offset=offset))
        if pagenum > 0:
            add_link(req, 'prev', req.href.admin(cat, page, page=pagenum),
                     'Previous Page')
        if offset + self.MAX_PER_PAGE < total:
            add_link(req, 'next', req.href.admin(cat, page, page=pagenum+2),
                     'Next Page')

        return {
            'enabled': FilterSystem(self.env).logging_enabled,
            'entries': entries,
            'offset': offset + 1,
            'page': pagenum + 1,
            'total': total
        }

    def _render_monitoring_entry(self, req, cat, page, entry_id):
        req.perm.assert_permission('SPAM_MONITOR')

        entry = LogEntry.fetch(self.env, entry_id)
        if not entry:
            raise HTTPNotFound('Log entry not found')

        previous = entry.get_previous()
        if previous:
            add_link(req, 'prev', req.href.admin(cat, page, previous.id),
                     'Log Entry %d' % previous.id)
        add_link(req, 'up', req.href.admin(cat, page), 'Log Entry List')
        next = entry.get_next()
        if next:
            add_link(req, 'next', req.href.admin(cat, page, next.id),
                     'Log Entry %d' % next.id)

        return {'entry': entry}

    def _process_monitoring_panel(self, req):
        req.perm.assert_permission('SPAM_TRAIN')

        filtersys = FilterSystem(self.env)

        if 'markspam' in req.args or 'markham' in req.args:
            spam = 'markspam' in req.args
            for entry_id in req.args.getlist('sel'):
                filtersys.train(req, entry_id, spam=spam)

        elif 'delete' in req.args:
            for entry_id in req.args.getlist('sel'):
                LogEntry.delete(self.env, entry_id)

        return True


def _entry_to_hdf(req, entry):
    return {
        'id': entry.id,
        'time': format_datetime(entry.time),
        'timedelta': pretty_timedelta(entry.time),
        'path': entry.path,
        'url': req.abs_href(entry.path),
        'path_clipped': shorten_line(entry.path, 25),
        'href': req.href(entry.path),
        'admin_href': req.href.admin('spamfilter', 'monitor', entry.id),
        'author': entry.author,
        'author_clipped': shorten_line(entry.author, 25),
        'ipnr': entry.ipnr,
        'authenticated': entry.authenticated,
        'headers': entry.headers,
        'content': shorten_line(entry.content),
        'full_content': entry.content,
        'rejected': entry.rejected,
        'karma': entry.karma, 'reasons': entry.reasons
    }


class AkismetAdminPageProvider(Component):
    """Web administration panel for configuring the Akismet spam filter."""

    if IAdminPanelProvider:
        implements(IAdminPanelProvider)
    elif IAdminPageProvider:
        implements(IAdminPageProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', 'Spam Filtering', 'akismet', 'Akismet')

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CONFIG')

        akismet = AkismetFilterStrategy(self.env)
        data = {}

        if req.method == 'POST':
            if 'cancel' in req.args:
                req.redirect(req.href.admin(cat, page))

            api_url = req.args.get('api_url')
            api_key = req.args.get('api_key')
            try:
                if not akismet._verify_key(req, api_url, api_key):
                    data['error'] = 'The API key is invalid'
                else:
                    self.config.set('spam-filter', 'akismet_api_url', api_url)
                    self.config.set('spam-filter', 'akismet_api_key', api_key)
                    self.config.save()
                    req.redirect(req.href.admin(cat, page))
            except urllib2.URLError, e:
                data['error'] = e.reason[1]

        else:
            api_url = akismet.api_url
            api_key = akismet.api_key

        data.update({'api_key': api_key, 'api_url': api_url})

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_akismet.html', data

    # IAdminPanelProvider methods

    get_admin_pages = get_admin_panels

    def process_admin_request(self, req, cat, page, path_info):
        template, data = self.render_admin_panel(req, cat, page, path_info)

        req.hdf['admin.akismet'] = data
        return template.replace('.html', '.cs'), None


class BayesAdminPageProvider(Component):
    """Web administration panel for configuring the Bayes spam filter."""

    if BayesianFilterStrategy:
        if IAdminPanelProvider:
            implements(IAdminPanelProvider)
        elif IAdminPageProvider:
            implements(IAdminPageProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', 'Spam Filtering', 'bayes', 'Bayes')

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CONFIG')

        bayes = BayesianFilterStrategy(self.env)
        hammie = bayes._get_hammie()
        data = {}

        if req.method == 'POST':
            if 'train' in req.args:
                bayes.train(None, None, req.args['content'],
                            spam='spam' in req.args['train'].lower())
                req.redirect(req.href.admin(cat, page))

            elif 'test' in req.args:
                data['content'] = req.args['content']
                try:
                    data['score'] = hammie.score(req.args['content'].encode('utf-8'))
                except Exception, e:
                    self.log.warn('Bayes test failed: %s', e, exc_info=True)
                    data['error'] = unicode(e)

            else:
                if 'reset' in req.args:
                    self.log.info('Resetting SpamBayes training database')
                    db = self.env.get_db_cnx()
                    cursor = db.cursor()
                    cursor.execute("DELETE FROM spamfilter_bayes")
                    db.commit()

                try:
                    min_training = int(req.args['min_training'])
                    if min_training != bayes.min_training:
                        self.config.set('spam-filter', 'bayes_min_training',
                                        min_training)
                        self.config.save()
                except ValueError:
                    pass
                req.redirect(req.href.admin(cat, page))

        data.update({'min_training': bayes.min_training,
                     'nspam': hammie.bayes.nspam,
                     'nham': hammie.bayes.nham})

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_bayes.html', data

    # IAdminPanelProvider methods

    get_admin_pages = get_admin_panels

    def process_admin_request(self, req, cat, page, path_info):
        template, data = self.render_admin_panel(req, cat, page, path_info)

        if 'score' in data:
            data['score'] = '%.2f' % (data['score'] * 100)

        req.hdf['admin.bayes'] = data
        return template.replace('.html', '.cs'), None
