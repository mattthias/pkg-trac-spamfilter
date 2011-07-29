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

from math import ceil
import re
from pkg_resources import parse_version

from trac import __version__ as VERSION
from trac.config import IntOption
from trac.core import *
from trac.db import DatabaseManager
from trac.wiki.api import IWikiChangeListener
from trac.wiki.model import WikiPage
from tracspamfilter.api import IFilterStrategy

from spambayes.hammie import Hammie
from spambayes.storage import SQLClassifier


class BayesianFilterStrategy(Component):
    """Bayesian filtering strategy based on SpamBayes."""

    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'bayes_karma', '10',
        """By what factor Bayesian spam probability score affects the overall
        karma of a submission.""")

    min_training = IntOption('spam-filter', 'bayes_min_training', '25',
        """The minimum number of submissions in the training database required
        for the filter to start impacting the karma of submissions.""")

    # IFilterStrategy implementation

    def test(self, req, author, content):
        hammie = self._get_hammie()
        nspam = hammie.bayes.nspam
        nham = hammie.bayes.nham

        if min(nspam, nham) < self.min_training:
            self.log.info('Bayes filter strategy requires more training. '
                          'It currently has only %d words marked as ham, and '
                          '%d marked as spam, but requires at least %d for '
                          'each.', nham, nspam, self.min_training)
            return

        if nham - nspam > min(nham, nspam) * 2:
            self.log.warn('The difference between the number of ham versus '
                          'spam submissions in the training database is large, '
                          'results may be bad.')

        score = hammie.score(content.encode('utf-8'))
        self.log.debug('SpamBayes reported spam probability of %s', score)
        points = -int(round(self.karma_points * (score * 2 - 1)))
        if points != 0:
            return points, 'SpamBayes determined spam probability of %.2f%%' % (
                           score * 100)

    def train(self, req, author, content, spam=True):
        self.log.info('Training SpamBayes, marking content as %s',
                      spam and 'spam' or 'ham')

        hammie = self._get_hammie()
        hammie.train(content.encode('utf-8'), spam)
        hammie.store()

    # Internal methods

    def _get_hammie(self):
        return Hammie(TracDbClassifier(self.env.get_db_cnx()))

    def _get_numbers(self):
        hammie = self._get_hammie()
        return hammie.nspam, hammie.nham


class TracDbClassifier(SQLClassifier):
    # FIXME: This thing is incredibly slow

    def __init__(self, db):
        self.db = db
        SQLClassifier.__init__(self, 'Trac')

    def load(self):
        if self._has_key(self.statekey):
            row = self._get_row(self.statekey)
            self.nspam = row['nspam']
            self.nham = row['nham']
        else: # new database
            self.nspam = self.nham = 0

    def _get_row(self, word):
        cursor = self.db.cursor()
        cursor.execute("SELECT nspam,nham FROM spamfilter_bayes WHERE word=%s",
                       (word,))
        row = cursor.fetchone()
        if not row:
            return {}

        return {'nspam': row[0], 'nham': row[1]}

    def _set_row(self, word, nspam, nham):
        cursor = self.db.cursor()
        if self._has_key(word):
            cursor.execute("UPDATE spamfilter_bayes SET nspam=%s,nham=%s "
                           "WHERE word=%s", (nspam, nham, word))
        else:
            cursor.execute("INSERT INTO spamfilter_bayes (word,nspam,nham) "
                           "VALUES (%s,%s,%s)", (word, nspam, nham))
        self.db.commit()

    def _delete_row(self, word):
        cursor = self.db.cursor()
        cursor.execute("DELETE FROM spamfilter_bayes WHERE word=%s", (word,))
        self.db.commit()

    def _has_key(self, key):
        cursor = self.db.cursor()
        cursor.execute("SELECT COUNT(*) FROM spamfilter_bayes WHERE word=%s",
                       (key,))
        return bool(cursor.fetchone()[0])

    def _wordinfoget(self, word):
        # See http://mail.python.org/pipermail/spambayes-dev/2006-July/003684.html
        if isinstance(word, unicode):
            word = word.encode("utf-8")

        row = self._get_row(word)
        if row:
            item = self.WordInfoClass()
            item.__setstate__((row["nspam"], row["nham"]))
            return item
        else:
            return None

    def _wordinfokeys(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT word FROM spamfilter_bayes")
        return [row[0] for row in cursor.fetchall()]
