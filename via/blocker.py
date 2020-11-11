from __future__ import unicode_literals

import os
import re

from jinja2 import Environment, FileSystemLoader
from pkg_resources import resource_filename
from urlparse import urlparse
from werkzeug import wsgi
from werkzeug.wrappers import BaseResponse as Response

DEFAULT_BLOCKLIST_PATH = resource_filename("via", "default-blocklist.txt")
TEMPLATES_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../templates/"


class Blocker(object):

    """
    Blocker is a WSGI middleware that returns a static response when a
    request path matches a list of predefined domains.

    The list of domains and the associated reasons for blocking them are defined
    in a text file with lines in the form:

    <domain> <reason>

    Where "<reason>" is one of "publisher-blocked" or "blocked". Any lines
    beginning with '#' are ignored. Any lines not in the above form are ignored.

    The domain can contain wildcards like this: '*.example.com'
    """

    def __init__(self, application, blocklist_path=DEFAULT_BLOCKLIST_PATH):
        self._application = application
        self._jinja_env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR), trim_blocks=True
        )

        self._blocklist_path = blocklist_path

        # dict of domain to block reason.
        self._blocked_domains_exact = {}

        # mtime of the blocklist file when it was last parsed.
        self._blocklist_timestamp = 0

        self._update_blocklist()

    def __call__(self, environ, start_response):
        self._update_blocklist()

        url_to_annotate = wsgi.get_path_info(environ)[1:]
        parsed_url = urlparse(url_to_annotate)

        if not parsed_url.scheme:
            url_to_annotate = "http://" + url_to_annotate
            parsed_url = urlparse(url_to_annotate)

        reason = self._match_domain(domain=parsed_url.hostname)
        if reason:
            if reason == "publisher-blocked":
                template_name = "disallow_access.html.jinja2"
                status = 451
            else:
                template_name = "could_not_process.html.jinja2"
                status = 200

            template = self._jinja_env.get_template(template_name).render(
                url_to_annotate=url_to_annotate
            )
            resp = Response(template, status=status, mimetype="text/html")
            return resp(environ, start_response)

        return self._application(environ, start_response)

    def _match_domain(self, domain):
        if domain is None:
            return

        if domain in self._blocked_domains_exact:
            return self._blocked_domains_exact[domain]

        for pattern, reason in self._blocked_domains_pattern.iteritems():
            if pattern.match(domain):
                return reason

        return None

    def _update_blocklist(self):
        blocklist_stinfo = os.stat(self._blocklist_path)
        if blocklist_stinfo.st_mtime == self._blocklist_timestamp:
            return

        self._blocked_domains_exact, self._blocked_domains_pattern = _parse_blocklist(
            self._blocklist_path
        )
        self._blocklist_timestamp = blocklist_stinfo.st_mtime


def _wildcard_to_regex(domain):
    """Convert a string with '*' wildcards into a regex."""

    pattern = "^" + re.escape(domain).replace("\\*", ".*") + "$"
    return re.compile(pattern, re.IGNORECASE)


def _parse_blocklist(path):
    blocked_domains_exact = {}
    blocked_domains_pattern = {}

    with open(path) as blocklist:
        for line in blocklist:
            line = line.strip()

            if not line or line.startswith("#"):
                # Empty or comment line.
                continue

            try:
                domain, reason = line.split(" ")
                if "*" in domain:
                    pattern = _wildcard_to_regex(domain)
                    blocked_domains_pattern[pattern] = reason
                else:
                    blocked_domains_exact[domain] = reason
            except Exception:
                pass

    return blocked_domains_exact, blocked_domains_pattern
