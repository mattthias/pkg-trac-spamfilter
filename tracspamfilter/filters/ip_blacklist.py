# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# Copyright (C) 2006 Matthew Good <trac@matt-good.net>
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

from dns.resolver import query, Timeout, NXDOMAIN, NoAnswer, NoNameservers

from trac.config import ListOption, IntOption
from trac.core import *
from trac.util import reversed
from tracspamfilter.api import IFilterStrategy


class IPBlacklistFilterStrategy(Component):
    """Spam filter based on IP blacklistings.
    
    Requires the dnspython module from http://www.dnspython.org/.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'ip_blacklist_karma', '5',
        """By how many points blacklisting by a single server impacts the
        overall karma of a submission.""")

    servers = ListOption('spam-filter', 'ip_blacklist_servers',
                         'bsb.empty.us, sc.surbl.org', doc=
        """Servers used for IP blacklisting.""")

    # IFilterStrategy implementation

    def test(self, req, author, content):
        if not self.servers:
            self.log.warning('No IP blacklist servers configured')
            return

        self.log.debug('Checking for IP blacklisting on "%s"' % req.remote_addr)

        points = 0
        servers = []

        prefix = '.'.join(reversed(req.remote_addr.split('.'))) + '.'
        for server in self.servers:
            try:
                query(prefix + server.encode('utf-8'))
            except NXDOMAIN: # not blacklisted on this server
                continue
            except (Timeout, NoAnswer, NoNameservers), e:
                self.log.warning('Error checking IP blacklist server "%s" for '
                                 'IP "%s": %s' % (server, req.remote_addr, e))
            else:
                points -= abs(self.karma_points)
                servers.append(server)

        if points != 0:
            return points, 'IP %s blacklisted by %s' % (req.remote_addr,
                                                        ', '.join(servers))

    def train(self, req, author, content, spam=True):
        pass
