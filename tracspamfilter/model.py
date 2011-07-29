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

import binascii

from datetime import datetime, timedelta
from time import mktime

from trac.db import Column, Index, Table
from trac.util.text import to_unicode

__all__ = ['LogEntry']


class LogEntry(object):

    table = Table('spamfilter_log', key='id')[
        Column('id', auto_increment=True),
        Column('time', type='int'),
        Column('path'),
        Column('author'),
        Column('authenticated', type='int'),
        Column('ipnr'),
        Column('headers'),
        Column('content'),
        Column('rejected', type='int'),
        Column('karma', type='int'),
        Column('reasons')
    ]

    def __init__(self, env, time, path, author, authenticated, ipnr, headers,
                 content, rejected, karma, reasons):
        self.id = None
        self.env = env
        self.time = time
        self.path = path
        self.author = author
        self.authenticated = bool(authenticated)
        self.ipnr = ipnr
        self.headers = headers or ''
        self.content = content
        self.rejected = bool(rejected)
        self.karma = karma
        if isinstance(reasons, basestring):
            if reasons:
                self.reasons = reasons.split('\n')
            else:
                self.reasons = []
        elif reasons is not None:
            self.reasons = list(reasons)
        else:
            self.reasons = []

    def __repr__(self):
        date = datetime.fromtimestamp(self.time).isoformat()
        return '<%s %s from %s by "%s">' % (self.__class__.__name__, self.id,
                                            date, self.author)

    exists = property(fget=lambda self: self.id is not None,
                      doc='Whether this log entry exists in the database')

    def _encode_content(cls, content):
        """Take a `basestring` content and return a plain text encoding."""
        return to_unicode(content).encode('utf-8').encode('base64')

    _encode_content = classmethod(_encode_content)

    def _decode_content(cls, content):
        """Revert the encoding done by `_encode_content` and return an unicode
        string"""
        try:
            return to_unicode(content.decode('base64'))
        except (UnicodeEncodeError, binascii.Error):
            # cope with legacy content (stored before base64 encoding)
            return to_unicode(content)

    _decode_content = classmethod(_decode_content)

    def get_next(self, db=None):
        """Return the next log entry in reverse chronological order (i.e. the
        next older entry.)"""
        if not db:
            db = self.env.get_db_cnx()

        cursor = db.cursor()
        cursor.execute("SELECT id,time,path,author,authenticated,ipnr,headers,"
                       "content,rejected,karma,reasons FROM spamfilter_log "
                       "WHERE id<%s ORDER BY id DESC LIMIT 1", (self.id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self.__class__._from_db(self.env, row)

    def get_previous(self, db=None):
        """Return the previous log entry in reverse chronological order
        (i.e. the next younger entry.)"""
        if not db:
            db = self.env.get_db_cnx()

        cursor = db.cursor()
        cursor.execute("SELECT id,time,path,author,authenticated,ipnr,headers,"
                       "content,rejected,karma,reasons FROM spamfilter_log "
                       "WHERE id>%s ORDER BY id LIMIT 1", (self.id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self.__class__._from_db(self.env, row)

    def insert(self, db=None):
        """Insert a new log entry into the database."""
        if not db:
            db = self.env.get_db_cnx()
            handle_ta = True
        else:
            handle_ta = False

        assert not self.exists, 'Cannot insert existing log entry'

        content = self._encode_content(self.content)

        cursor = db.cursor()
        cursor.execute("INSERT INTO spamfilter_log (time,path,author,"
                       "authenticated,ipnr,headers,content,rejected,"
                       "karma,reasons) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                       "%s)", (int(self.time), self.path, self.author,
                       int(bool(self.authenticated)), self.ipnr, self.headers,
                       content, int(bool(self.rejected)), int(self.karma),
                       '\n'.join(self.reasons)))
        self.id = db.get_last_id(cursor, 'spamfilter_log')
        if handle_ta:
            db.commit()

    def update(self, db=None, **kwargs):
        """Update the log entry in the database."""
        if not db:
            db = self.env.get_db_cnx()
            handle_ta = True
        else:
            handle_ta = False

        assert self.exists, 'Cannot update a non-existing log entry'

        for name, value in kwargs.items():
            if hasattr(self, name):
                setattr(self, name, value)

        content = self._encode_content(self.content)
        
        cursor = db.cursor()
        cursor.execute("UPDATE spamfilter_log SET time=%s,path=%s,author=%s,"
                       "authenticated=%s,ipnr=%s,headers=%s,content=%s,"
                       "rejected=%s,karma=%s,reasons=%s WHERE id=%s", (
                       int(self.time), self.path, self.author,
                       int(bool(self.authenticated)), self.ipnr, self.headers,
                       content, int(bool(self.rejected)), int(self.karma),
                       '\n'.join(self.reasons), self.id))
        if handle_ta:
            db.commit()

    def delete(cls, env, id, db=None):
        """Delete the log entry with the specified ID from the database."""
        if not db:
            db = env.get_db_cnx()
            handle_ta = True
        else:
            handle_ta = False

        cursor = db.cursor()
        cursor.execute("DELETE FROM spamfilter_log WHERE id=%s", (id,))
        if handle_ta:
            db.commit()

    delete = classmethod(delete)

    def fetch(cls, env, id, db=None):
        """Retrieve an existing log entry from the database by ID."""
        if not db:
            db = env.get_db_cnx()

        cursor = db.cursor()
        cursor.execute("SELECT id,time,path,author,authenticated,ipnr,headers,"
                       "content,rejected,karma,reasons FROM spamfilter_log "
                       "WHERE id=%s", (int(id),))
        row = cursor.fetchone()
        if not row:
            return None
        return cls._from_db(env, row)

    fetch = classmethod(fetch)

    def count(cls, env, db=None):
        """Return the number of log entries in the database."""
        if not db:
            db = env.get_db_cnx()

        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM spamfilter_log ")
        return cursor.fetchone()[0]

    count = classmethod(count)

    def purge(cls, env, days, db=None):
        """Delete log entries older than the specified number of days."""
        if not db:
            db = env.get_db_cnx()
            handle_ta = True
        else:
            handle_ta = False

        threshold = datetime.now() - timedelta(days=days)
        cursor = db.cursor()
        cursor.execute("DELETE FROM spamfilter_log WHERE time < %s",
                       (mktime(threshold.timetuple()),))
        if handle_ta:
            db.commit()

    purge = classmethod(purge)

    def select(cls, env, ipnr=None, limit=None, offset=0, db=None):
        """Retrieve existing log entries from the database that match the
        specified criteria.
        """
        if not db:
            db = env.get_db_cnx()

        extra_clauses = []
        params = []

        where_clauses = []
        if ipnr:
            where_clauses.append("ipnr=%s")
            params.append(ipnr)

        if where_clauses:
            where = "WHERE %s" % " AND ".join(where_clauses)
        else:
            where = ""

        if limit:
            extra_clauses.append("LIMIT %s")
            params.append(limit)
            if offset:
                extra_clauses.append("OFFSET %s")
                params.append(offset)
        if extra_clauses:
            extra = " ".join(extra_clauses)
        else:
            extra = ""

        cursor = db.cursor()
        cursor.execute("SELECT id,time,path,author,authenticated,ipnr,headers,"
                       "content,rejected,karma,reasons FROM spamfilter_log "
                       "%s ORDER BY time DESC %s" % (where, extra), params)
        for row in cursor:
            yield cls._from_db(env, row)

    select = classmethod(select)

    def _from_db(cls, env, row):
        """Create a new LogEntry from a row from the `spamfilter_log` table."""
        fields = list(row[1:])
        fields[6] = cls._decode_content(fields[6])
        obj = cls(env, *fields)
        obj.id = row[0]
        return obj

    _from_db = classmethod(_from_db)

class Bayes(object):

    table = Table('spamfilter_bayes', key='word')[
        Column('word'),
        Column('nspam', type='int'),
        Column('nham', type='int'),
        Index(['word'])
    ]


schema = [Bayes.table, LogEntry.table]
schema_version = 3
