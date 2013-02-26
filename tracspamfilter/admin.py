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
from trac.admin import IAdminPanelProvider
from trac.config import IntOption
from trac.core import *
from trac.util import format_datetime, pretty_timedelta, shorten_line, sorted
from trac.web import Request, HTTPNotFound
from trac.web.chrome import add_link, add_stylesheet, ITemplateProvider
from tracspamfilter.filtersystem import FilterSystem
from tracspamfilter.api import add_domain, _, N_, gettext
from tracspamfilter.model import LogEntry
from tracspamfilter.filters.akismet import AkismetFilterStrategy
from tracspamfilter.filters.spamwipe import SpamWipeFilterStrategy
from tracspamfilter.filters.stopforumspam import StopForumSpamFilterStrategy
from tracspamfilter.filters.spambusted import SpamBustedFilterStrategy
from tracspamfilter.filters.botscout import BotScoutFilterStrategy
from tracspamfilter.filters.fspamlist import FSpamListFilterStrategy
from tracspamfilter.filters.blogspam import BlogSpamFilterStrategy
from tracspamfilter.filters.typepad import TypePadFilterStrategy
from tracspamfilter.captcha import ICaptchaMethod
from tracspamfilter.captcha.recaptcha import RecaptchaCaptcha
from tracspamfilter.captcha.keycaptcha import KeycaptchaCaptcha
from tracspamfilter.captcha.areyouahuman import AreYouAHumanCaptcha
try:
    from tracspamfilter.filters.defensio import DefensioFilterStrategy
except ImportError: # Defensio not installed
    DefensioFilterStrategy = None
try:
    from tracspamfilter.filters.bayes import BayesianFilterStrategy
except ImportError: # SpamBayes not installed
    BayesianFilterStrategy = None
try:
    from tracspamfilter.filters.httpbl import HttpBLFilterStrategy
except ImportError: # DNS python not installed
    HttpBLFilterStrategy = None
try:
    from tracspamfilter.captcha.image import ImageCaptcha
except ImportError: # PIL not installed
    ImageCaptcha = None

class SpamFilterAdminPageProvider(Component):
    """Web administration panel for configuring and monitoring the spam
    filtering system.
    """

    implements(ITemplateProvider)
    implements(IAdminPanelProvider)

    MAX_PER_PAGE = 1000
    MIN_PER_PAGE = 5
    DEF_PER_PAGE =  IntOption('spam-filter', 'spam_monitor_entries', '15',
    "How many monitor entries are displayed by default (between 5 and 1000).",
    doc_domain='tracspamfilter')

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', _("Spam Filtering"), 'config', 
                   _("Configuration"))
        if req.perm.has_permission('SPAM_MONITOR'):
            yield ('spamfilter', _("Spam Filtering"), 'monitor',
                   _("Monitoring"))

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
                                                page=req.args.get('page'),
                                                num=req.args.get('num')))
            if path_info:
                data = self._render_monitoring_entry(req, cat, page, path_info)
                page = 'entry'
            else:
                data = self._render_monitoring_panel(req, cat, page)

        add_stylesheet(req, 'spamfilter/admin.css')
        data['_'] = _
        return 'admin_spam%s.html' % page, data

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
                    'karma_help': gettext(strategy.__class__.karma_points.__doc__)}
            strategies.append(info)

        return {
            'strategies': sorted(strategies, key=lambda x: x['name']),
            'min_karma': filtersys.min_karma,
            'authenticated_karma': filtersys.authenticated_karma,
            'attachment_karma': filtersys.attachment_karma,
            'trust_authenticated': filtersys.trust_authenticated,
            'logging_enabled': filtersys.logging_enabled,
            'purge_age': filtersys.purge_age,
            'spam_monitor_entries_min' : self.MIN_PER_PAGE,
            'spam_monitor_entries_max' : self.MAX_PER_PAGE,
            'spam_monitor_entries' : self.DEF_PER_PAGE
        }

    def _process_config_panel(self, req):
        req.perm.assert_permission('SPAM_CONFIG')

        try:
            min_karma = int(req.args.get('min_karma'))
            self.config.set('spam-filter', 'min_karma', min_karma)
        except:
            pass

        try:
            attachment_karma = int(req.args.get('attachment_karma'))
            self.config.set('spam-filter', 'attachment_karma', attachment_karma)
        except:
            pass

        try:
            authenticated_karma = int(req.args.get('authenticated_karma'))
            self.config.set('spam-filter', 'authenticated_karma', authenticated_karma)
        except:
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

        trust_authenticated = 'trust_authenticated' in req.args
        self.config.set('spam-filter', 'trust_authenticated',
                        str(trust_authenticated).lower())

        if logging_enabled:
            try:
                purge_age = int(req.args.get('purge_age'))
                self.config.set('spam-filter', 'purge_age', purge_age)
            except ValueError:
                pass

        try:
            spam_monitor_entries = int(req.args.get('spam_monitor_entries'))
            if spam_monitor_entries < self.MIN_PER_PAGE:
                spam_monitor_entries = self.MIN_PER_PAGE
            elif spam_monitor_entries > self.MAX_PER_PAGE:
                spam_monitor_entries = self.MAX_PER_PAGE
            self.config.set('spam-filter', 'spam_monitor_entries', spam_monitor_entries)
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

        try:
            pagesize = int(req.args.get('num', self.DEF_PER_PAGE))
        except ValueError:
            pagesize = self.DEF_PER_PAGE
        if pagesize < self.MIN_PER_PAGE:
            pagesize = self.MIN_PER_PAGE
        elif pagesize > self.MAX_PER_PAGE:
            pagesize = self.MAX_PER_PAGE

        total = LogEntry.count(self.env)

        if total < pagesize:
            pagenum = 0
        elif total <= pagenum * pagesize:
            pagenum = (total-1)/pagesize

        offset = pagenum * pagesize
        entries = list(LogEntry.select(self.env, limit=pagesize,
                                       offset=offset))
        if pagenum > 0:
            add_link(req, 'prev', req.href.admin(cat, page, page=pagenum,
                                                 num=pagesize),
                     _('Previous Page'))
        if offset + pagesize < total:
            add_link(req, 'next', req.href.admin(cat, page, page=pagenum+2,
                                                 num=pagesize),
                     _('Next Page'))

        return {
            'enabled': FilterSystem(self.env).logging_enabled,
            'entries': entries,
            'offset': offset + 1,
            'page': pagenum + 1,
            'num': pagesize,
            'total': total
        }

    def _render_monitoring_entry(self, req, cat, page, entry_id):
        req.perm.assert_permission('SPAM_MONITOR')

        entry = LogEntry.fetch(self.env, entry_id)
        if not entry:
            raise HTTPNotFound(_('Log entry not found'))

        previous = entry.get_previous()
        if previous:
            add_link(req, 'prev', req.href.admin(cat, page, previous.id),
                     _('Log Entry %d') % previous.id)
        add_link(req, 'up', req.href.admin(cat, page), _('Log Entry List'))
        next = entry.get_next()
        if next:
            add_link(req, 'next', req.href.admin(cat, page, next.id),
                     _('Log Entry %d') % next.id)

        return {'entry': entry}

    def _process_monitoring_panel(self, req):
        req.perm.assert_permission('SPAM_TRAIN')

        filtersys = FilterSystem(self.env)

        spam = 'markspam' in req.args or 'markspamdel' in req.args
        train = spam or 'markham' in req.args or 'markhamdel' in req.args
        delete = 'delete' in req.args or 'markspamdel' in req.args \
        or 'markhamdel' in req.args
        

        if train or delete:
            for entry_id in req.args.getlist('sel'):
                if train:
                    filtersys.train(req, entry_id, spam=spam)
                if delete:
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


class ExternalAdminPageProvider(Component):
    """Web administration panel for configuring the External spam filters."""

    implements(IAdminPanelProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', _("Spam Filtering"), 'external', _("External"))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CONFIG')

        data = {}

        typepad = TypePadFilterStrategy(self.env)
        akismet = AkismetFilterStrategy(self.env)
        spamwipe = SpamWipeFilterStrategy(self.env)
        stopforumspam = StopForumSpamFilterStrategy(self.env)
        spambusted = SpamBustedFilterStrategy(self.env)
        botscout = BotScoutFilterStrategy(self.env)
        fspamlist = FSpamListFilterStrategy(self.env)
        blogspam = BlogSpamFilterStrategy(self.env)
        defensio = 0
        if DefensioFilterStrategy:
            defensio = DefensioFilterStrategy(self.env)
 
        if req.method == 'POST':
            if 'cancel' in req.args:
                req.redirect(req.href.admin(cat, page))

            akismet_api_url = req.args.get('akismet_api_url')
            akismet_api_key = req.args.get('akismet_api_key')
            spamwipe_api_key = req.args.get('spamwipe_api_key')
            defensio_api_url = req.args.get('defensio_api_url')
            defensio_api_key = req.args.get('defensio_api_key')
            typepad_api_url = req.args.get('typepad_api_url')
            typepad_api_key = req.args.get('typepad_api_key')
            stopforumspam_api_key = req.args.get('stopforumspam_api_key')
            spambusted_api_key = req.args.get('spambusted_api_key')
            botscout_api_key = req.args.get('botscout_api_key')
            fspamlist_api_key = req.args.get('fspamlist_api_key')
            httpbl_api_key = req.args.get('httpbl_api_key')
            ip_blacklist_servers = req.args.get('ip_blacklist_servers')
            blogspam_api_url = req.args.get('blogspam_api_url')
            blogspam_skip_tests = req.args.get('blogspam_skip_tests')
            use_external = 'use_external' in req.args
            train_external = 'train_external' in req.args
            try:
                if akismet_api_key and not akismet.verify_key(req, akismet_api_url, akismet_api_key):
                    data['akismeterror'] = 'The API key is invalid'
                    data['error'] = 1
                elif typepad_api_key and not typepad.verify_key(req, typepad_api_url, typepad_api_key):
                    data['typepaderror'] = 'The API key is invalid'
                    data['error'] = 1
                elif defensio and defensio_api_key and not defensio.verify_key(req, defensio_api_url, defensio_api_key):
                    data['defensioerror'] = 'The API key is invalid'
                    data['error'] = 1
                elif spamwipe_api_key and not spamwipe.verify_key(req, spamwipe_api_key):
                    data['spamwipeerror'] = 'The API key is invalid'
                    data['error'] = 1
                else:
                    self.config.set('spam-filter', 'akismet_api_url', akismet_api_url)
                    self.config.set('spam-filter', 'akismet_api_key', akismet_api_key)
                    self.config.set('spam-filter', 'spamwipe_api_key', spamwipe_api_key)
                    self.config.set('spam-filter', 'defensio_api_url', defensio_api_url)
                    self.config.set('spam-filter', 'defensio_api_key', defensio_api_key)
                    self.config.set('spam-filter', 'typepad_api_url', typepad_api_url)
                    self.config.set('spam-filter', 'typepad_api_key', typepad_api_key)
                    self.config.set('spam-filter', 'stopforumspam_api_key', stopforumspam_api_key)
                    self.config.set('spam-filter', 'spambusted_api_key', spambusted_api_key)
                    self.config.set('spam-filter', 'botscout_api_key', botscout_api_key)
                    self.config.set('spam-filter', 'fspamlist_api_key', fspamlist_api_key)
                    self.config.set('spam-filter', 'httpbl_api_key', httpbl_api_key)
                    self.config.set('spam-filter', 'ip_blacklist_servers', ip_blacklist_servers)
                    self.config.set('spam-filter', 'blogspam_api_url', blogspam_api_url)
                    self.config.set('spam-filter', 'blogspam_skip_tests', blogspam_skip_tests)
                    self.config.set('spam-filter', 'use_external', str(use_external).lower())
                    self.config.set('spam-filter', 'train_external', str(train_external).lower())
                    self.config.save()
                    req.redirect(req.href.admin(cat, page))
            except urllib2.URLError, e:
                data['unknownsourceerror'] = e.reason[1]
                data['error'] = 1

        else:
            filtersys = FilterSystem(self.env)
            use_external = filtersys.use_external
            train_external = filtersys.train_external
            blogspam_api_url = blogspam.api_url
            blogspam_skip_tests = ",".join(blogspam.skip_tests)
            akismet_api_url = akismet.api_url
            akismet_api_key = akismet.api_key
            spamwipe_api_key = spamwipe.api_key
            if DefensioFilterStrategy:
                defensio_api_url = defensio.api_url
                defensio_api_key = defensio.api_key
            typepad_api_url = typepad.api_url
            typepad_api_key = typepad.api_key
            stopforumspam_api_key = stopforumspam.api_key
            spambusted_api_key = spambusted.api_key
            botscout_api_key = botscout.api_key
            fspamlist_api_key = fspamlist.api_key
            httpbl_api_key = self.config.get('spam-filter', 'httpbl_api_key')
            ip_blacklist_servers = self.config.get('spam-filter', 'ip_blacklist_servers')

        if HttpBLFilterStrategy:
            data['blacklists'] = 1
        if DefensioFilterStrategy:
            data['defensio'] = 1
            data['defensio_api_key'] = defensio_api_key
            data['defensio_api_url'] = defensio_api_url

        data['_'] = _
        data.update({'akismet_api_key': akismet_api_key, 'akismet_api_url': akismet_api_url,
                     'typepad_api_key': typepad_api_key, 'typepad_api_url': typepad_api_url,
                     'httpbl_api_key': httpbl_api_key, 'blogspam_api_url': blogspam_api_url,
                     'stopforumspam_api_key': stopforumspam_api_key,
                     'spambusted_api_key': spambusted_api_key,
                     'spamwipe_api_key': spamwipe_api_key,
                     'botscout_api_key': botscout_api_key,
                     'fspamlist_api_key': fspamlist_api_key,
                     'use_external' : use_external, 'train_external': train_external,
                     'blogspam_skip_tests': blogspam_skip_tests,
                     'blogspam_methods': ", ".join(blogspam.getmethods()),
                     'ip_blacklist_servers': ip_blacklist_servers})

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_external.html', data

class BayesAdminPageProvider(Component):
    """Web administration panel for configuring the Bayes spam filter."""

    if BayesianFilterStrategy:
        implements(IAdminPanelProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', _('Spam Filtering'), 'bayes', _('Bayes'))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CONFIG')

        bayes = BayesianFilterStrategy(self.env)
        hammie = bayes._get_hammie()
        data = {}

        if req.method == 'POST':
            if 'train' in req.args:
                bayes.train(None, None, req.args['bayes_content'], '127.0.0.1',
                            spam='spam' in req.args['train'].lower())
                req.redirect(req.href.admin(cat, page))

            elif 'test' in req.args:
                data['content'] = req.args['bayes_content']
                try:
                    data['score'] = hammie.score(req.args['bayes_content'].encode('utf-8'))
                except Exception, e:
                    self.log.warn('Bayes test failed: %s', e, exc_info=True)
                    data['error'] = unicode(e)

            else:
                if 'reset' in req.args:
                    self.log.info('Resetting SpamBayes training database')
                    env.db_transaction("DELETE FROM spamfilter_bayes")

                try:
                    min_training = int(req.args['min_training'])
                    if min_training != bayes.min_training:
                        self.config.set('spam-filter', 'bayes_min_training',
                                        min_training)
                        self.config.save()
                except ValueError:
                    pass
                req.redirect(req.href.admin(cat, page))
        ratio=""
        nspam = hammie.bayes.nspam
        nham = hammie.bayes.nham
        if nham and nspam:
            if nspam > nham:
                ratio = _("(ratio %.1f : 1)") % (float(nspam)/float(nham))
            else:
                ratio = _("(ratio 1 : %.1f)") % (float(nham)/float(nspam))

        data['_'] = _
        data.update({'min_training': bayes.min_training,
                     'nspam': nspam,
                     'nham': nham,
                     'ratio': ratio})

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_bayes.html', data

class CaptchaAdminPageProvider(Component):
    """Web administration panel for configuring the Captcha handling."""

    handlers = ExtensionPoint(ICaptchaMethod)    
    implements(IAdminPanelProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CONFIG'):
            yield ('spamfilter', _("Spam Filtering"), 'captcha', _("Captcha"))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CONFIG')

        recaptcha = RecaptchaCaptcha(self.env)
        keycaptcha = KeycaptchaCaptcha(self.env)
        areyouahuman = AreYouAHumanCaptcha(self.env)
        data = {}

        if req.method == 'POST':
            if 'cancel' in req.args:
                req.redirect(req.href.admin(cat, page))

            captcha_enabled = 'captcha_enabled' in req.args
            captcha = req.args.get('captcha')

            captcha_karma_lifetime = req.args.get('captcha_karma_lifetime')

            captcha_recaptcha_private_key = req.args.get('captcha_recaptcha_private_key')
            captcha_recaptcha_public_key = req.args.get('captcha_recaptcha_public_key')

            captcha_keycaptcha_private_key = req.args.get('captcha_keycaptcha_private_key')
            captcha_keycaptcha_user_id = req.args.get('captcha_keycaptcha_user_id')

            captcha_areyouahuman_publisher_key = req.args.get('captcha_areyouahuman_publisher_key')
            captcha_areyouahuman_scoring_key = req.args.get('captcha_areyouahuman_scoring_key')

            captcha_expression_ceiling = req.args.get('captcha_expression_ceiling')
            captcha_expression_terms = req.args.get('captcha_expression_terms')

            if ImageCaptcha:
                captcha_image_letters = req.args.get('captcha_image_letters')
                captcha_image_font_size = req.args.get('captcha_image_font_size')
                captcha_image_alphabet = req.args.get('captcha_image_alphabet')
                captcha_image_fonts = req.args.get('captcha_image_fonts')

            try:
                captcha_karma_lifetime = int(captcha_karma_lifetime)
            except:
                data['unknownsourceerror'] = _('Lifetime has invalid value')
                data['error'] = 1
            try:
                captcha_expression_ceiling = int(captcha_expression_ceiling)
                captcha_expression_terms = int(captcha_expression_terms)
            except:
                data['unknownsourceerror'] = _('Text values are not numeric')
                data['error'] = 1
            if ImageCaptcha:
                try:
                    captcha_image_letters = int(captcha_image_letters)
                    captcha_image_font_size = int(captcha_image_font_size)
                except:
                    data['unknownsourceerror'] = _('Numeric image values are no numbers')
                    data['error'] = 1
            try:
                if captcha_recaptcha_private_key and not recaptcha.verify_key(
                    captcha_recaptcha_private_key, captcha_recaptcha_public_key):
                    data['recaptchaerror'] = _('The keys are invalid')
                    data['error'] = 1
                elif captcha_keycaptcha_private_key and not keycaptcha.verify_key(
                    captcha_keycaptcha_private_key, captcha_keycaptcha_user_id):
                    data['keycaptchaerror'] = _('The key or user id are invalid')
                    data['error'] = 1
                elif captcha_areyouahuman_publisher_key and not areyouahuman.verify_key(
                    captcha_areyouahuman_publisher_key, captcha_areyouahuman_scoring_key):
                    data['areyouahumanerror'] = _('The keys are invalid')
                    data['error'] = 1
                elif not 'error' in data or not data['error']:
                    self.config.set('spam-filter', 'captcha', captcha)
                    if(captcha_enabled):
                        self.config.set('spam-filter', 'reject_handler', 'CaptchaSystem')
                    else:
                        self.config.set('spam-filter', 'reject_handler', 'FilterSystem')
                    self.config.set('spam-filter', 'captcha_karma_lifetime', captcha_karma_lifetime)

                    self.config.set('spam-filter', 'captcha_recaptcha_private_key', captcha_recaptcha_private_key)
                    self.config.set('spam-filter', 'captcha_recaptcha_public_key', captcha_recaptcha_public_key)

                    self.config.set('spam-filter', 'captcha_keycaptcha_private_key', captcha_keycaptcha_private_key)
                    self.config.set('spam-filter', 'captcha_keycaptcha_user_id', captcha_keycaptcha_user_id)

                    self.config.set('spam-filter', 'captcha_areyouahuman_publisher_key', captcha_areyouahuman_publisher_key)
                    self.config.set('spam-filter', 'captcha_areyouahuman_scoring_key', captcha_areyouahuman_scoring_key)

                    self.config.set('spam-filter', 'captcha_expression_ceiling', captcha_expression_ceiling)
                    self.config.set('spam-filter', 'captcha_expression_terms', captcha_expression_terms)

                    if ImageCaptcha:
                        self.config.set('spam-filter', 'captcha_image_alphabet', captcha_image_alphabet)
                        self.config.set('spam-filter', 'captcha_image_letters', captcha_image_letters)
                        self.config.set('spam-filter', 'captcha_image_font_size', captcha_image_font_size)
                        self.config.set('spam-filter', 'captcha_image_fonts', captcha_image_fonts)

                    self.config.save()
                    req.redirect(req.href.admin(cat, page))
            except urllib2.URLError, e:
                data['unknownsourceerror'] = e.reason[1]
                data['error'] = 1

        else:
            if self.config.get('spam-filter', 'reject_handler') == 'CaptchaSystem':
                captcha_enabled = True
            else:
                captcha_enabled = False
            captcha = self.config.get('spam-filter', 'captcha')
            captcha_karma_lifetime = self.config.get('spam-filter', 'captcha_karma_lifetime')

            captcha_recaptcha_private_key = self.config.get('spam-filter', 'captcha_recaptcha_private_key')
            captcha_recaptcha_public_key = self.config.get('spam-filter', 'captcha_recaptcha_public_key')

            captcha_keycaptcha_private_key = self.config.get('spam-filter', 'captcha_keycaptcha_private_key')
            captcha_keycaptcha_user_id = self.config.get('spam-filter', 'captcha_keycaptcha_user_id')

            captcha_areyouahuman_publisher_key = self.config.get('spam-filter', 'captcha_areyouahuman_publisher_key')
            captcha_areyouahuman_scoring_key = self.config.get('spam-filter', 'captcha_areyouahuman_scoring_key')

            captcha_expression_ceiling = self.config.get('spam-filter', 'captcha_expression_ceiling')
            captcha_expression_terms = self.config.get('spam-filter', 'captcha_expression_terms')

            if ImageCaptcha:
                captcha_image_alphabet = self.config.get('spam-filter', 'captcha_image_alphabet')
                captcha_image_letters = self.config.get('spam-filter', 'captcha_image_letters')
                captcha_image_font_size = self.config.get('spam-filter', 'captcha_image_font_size')
                captcha_image_fonts = self.config.get('spam-filter', 'captcha_image_fonts')

        if ImageCaptcha:
            data['imagecaptcha'] = 1
            data.update({'captcha_image_alphabet': captcha_image_alphabet,
                         'captcha_image_letters': captcha_image_letters,
                         'captcha_image_font_size': captcha_image_font_size,
                         'captcha_image_fonts': captcha_image_fonts})
        captchas = []
        for handler in self.handlers:
            captchas.append(handler.__class__.__name__)
        captchas.sort()

        data.update({'captcha': captcha,
                     'types': captchas,
                     'captcha_enabled': captcha_enabled,
                     'captcha_recaptcha_private_key': captcha_recaptcha_private_key,
                     'captcha_recaptcha_public_key': captcha_recaptcha_public_key,
                     'captcha_keycaptcha_private_key': captcha_keycaptcha_private_key,
                     'captcha_keycaptcha_user_id': captcha_keycaptcha_user_id,
                     'captcha_areyouahuman_publisher_key': captcha_areyouahuman_publisher_key,
                     'captcha_areyouahuman_scoring_key': captcha_areyouahuman_scoring_key,
                     'captcha_expression_ceiling': captcha_expression_ceiling,
                     'captcha_expression_terms': captcha_expression_terms,
                     'captcha_karma_lifetime': captcha_karma_lifetime})

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_captcha.html', data
