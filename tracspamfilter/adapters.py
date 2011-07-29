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

from StringIO import StringIO

from trac.attachment import IAttachmentManipulator
from trac.core import *
from trac.config import IntOption
from trac.mimeview import is_binary
from trac.ticket import ITicketManipulator, TicketSystem
from trac.util.text import to_unicode
from trac.wiki import WikiPage, IWikiPageManipulator
from tracspamfilter.api import FilterSystem


class TicketFilterAdapter(Component):
    implements(ITicketManipulator)

    # ITicketManipulator methods

    def prepare_ticket(self, req, ticket, fields, actions):
        pass

    def validate_ticket(self, req, ticket):
        if req.perm.has_permission('TICKET_ADMIN'):
            # An administrator is allowed to spam
            return []

        if 'preview' in req.args:
            # Only a preview, no need to filter the submission yet
            return []

        changes = []

        # Add the author/reporter name
        if not ticket.exists:
            author = ticket['reporter']
        else:
            author = req.args.get('author')
        if author:
            changes += [(None, author)]

        # Add any modified text fields of the ticket (except for the CC field)
        fields = [f['name'] for f in
                  TicketSystem(self.env).get_ticket_fields()
                  if f['type'] in ('textarea', 'text')]
        fields.remove('cc')
        for field in fields:
            if ticket.exists and field == 'description':
                continue
            if field in ticket._old:
                changes.append((ticket._old[field], ticket[field]))

        if 'comment' in req.args:
            changes.append((None, req.args.get('comment')))

        FilterSystem(self.env).test(req, author, changes)
        return []


class WikiFilterAdapter(Component):
    implements(IWikiPageManipulator)

    # ITicketManipulator methods

    def prepare_wiki_page(self, req, page, fields):
        pass

    def validate_wiki_page(self, req, page):
        if req.perm.has_permission('WIKI_ADMIN'):
            # An administrator is allowed to spam
            return []

        if 'preview' in req.args:
            # Only a preview, no need to filter the submission yet
            return []

        cur_page = WikiPage(self.env, name=page.name, version=page.version)
        author = req.args.get('author', req.authname)
        comment = req.args['comment']

        # Test the actual page changes as well as the comment
        changes = [(cur_page.text, page.text), (None, author)]
        if comment:
            changes += [(None, comment)]

        FilterSystem(self.env).test(req, author, changes)
        return []


class AttachmentFilterAdapter(Component):
    implements(IAttachmentManipulator)

    sample_size = IntOption('spam-filter', 'attachment_sample_size', 16384,
        """The number of bytes from an attachment to pass through the spam
        filters.""")

    # ITicketManipulator methods

    def prepare_attachment(self, req, attachment, fields):
        pass

    def validate_attachment(self, req, attachment):
        if req.perm.has_permission('WIKI_ADMIN'):
            # An administrator is allowed to spam
            return []

        author = req.args.get('author', req.authname)
        description = req.args['description']

        upload = req.args['attachment']
        content = ''
        try:
            data = upload.file.read(self.sample_size)
            if not is_binary(data):
                content = to_unicode(data)
        finally:
            upload.file.seek(0)
        filename = upload.filename

        changes = []
        for field in filter(None, [author, description, filename, content]):
            changes += [(None, field)]

        FilterSystem(self.env).test(req, author, changes)
        return []
