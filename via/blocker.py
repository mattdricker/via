from __future__ import unicode_literals

import os
import re
from logging import getLogger

from checkmatelib import CheckmateClient, CheckmateException
from jinja2 import Environment, FileSystemLoader
from urlparse import urlparse
from werkzeug import wsgi
from werkzeug.wrappers import BaseResponse as Response

LOG = getLogger(__name__)


class Blocker(object):
    template_dir = os.path.dirname(os.path.abspath(__file__)) + "/../templates/"

    # Map block reasons to specific templates and status codes
    templates = {
        "malicious": ["malicious_website_warning.html.jinja2", 200],
        "publisher-blocked": ["disallow_access.html.jinja2", 451],
        "other": ["could_not_process.html.jinja2", 200],
    }

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

    def __init__(self, application, checkmate_host=None):
        self._application = application
        self._jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir), trim_blocks=True
        )

        self._checkmate = CheckmateClient(checkmate_host)

    def __call__(self, environ, start_response):
        # Parse the URL and referrer
        request_path = wsgi.get_path_info(environ)
        via_host = environ.get("HTTP_HOST")
        classified_url = ClassifiedURL(request_path, via_host, assume_via=True)
        classified_referrer = ClassifiedURL(environ.get("HTTP_REFERER"), via_host)

        # Determine which urls should be run against checkmate (if any)
        full_check, partial_check, rule_type = self._apply_rules(
            classified_url, classified_referrer
        )

        # Apply the checks
        for classified_url, allow_all in ((full_check, False), (partial_check, True)):
            if not classified_url:
                # No check of this type requested
                continue

            hits = self._check_url(classified_url.effective_url, allow_all=allow_all)
            if not hits:
                continue

            response = self._render_block_template(hits, classified_url)
            return response(environ, start_response)

        return self._application(environ, start_response)

    @classmethod
    def _apply_rules(cls, url, referrer):
        """Determine what checks to make based on a URL and referrer.

        :param url: ClassifiedURL instance for the url being served
        :param referrer: ClassifiedURL instance for the referrer
        :return: A tuple of (full_check_url, partial_check_url, rule_type)
        """
        url_type, ref_type = url.type, referrer.type

        # Although we never return anything other than the original URL, the
        # system is written to be flexible enough to return the referrer
        # instead or both if we want to. This is to allow future tweaks to the
        # ruleset without major refactoring.

        if url_type == "via_landing_page":
            return None, None, "landing_page"

        if ref_type in ("via_page", "via_sub_resource"):
            return None, url, "sub_resource_check"

        return url, None, "page_to_check"

    def _check_url(self, url, allow_all=False):
        """Check a URL with checkmate."""

        try:
            return self._checkmate.check_url(url, allow_all=allow_all)

        except CheckmateException as err:
            LOG.warning(
                "Failed to check url against checkmate with error: {}".format(err)
            )
            return None

    def _render_block_template(self, hits, classified_url):
        template_name, status = self.templates.get(
            hits.reason_codes[0], self.templates["other"]
        )

        template = self._jinja_env.get_template(template_name).render(
            url_to_annotate=classified_url.effective_url,
            domain_to_annotate=classified_url.parsed.netloc,
        )
        return Response(template, status=status, mimetype="text/html")


class ClassifiedURL(object):
    """A URL with extra information about it's source."""

    SUB_RESOURCE_RE = re.compile(r"^/([a-z]{2})_/(.*)$")

    def __init__(self, raw_url, via_host, assume_via=False):
        """Parse a URL and determine it's features.

        :param raw_url: URL to parse
        :param via_host: The host Via is being served from
        :param assume_via: Assume this is a Via URL (rather than checking)
        """
        self.raw_url = raw_url
        self.parsed = None

        self.resource_type = None
        self.type, self.effective_url = self._classify(via_host, assume_via)

    def _classify(self, via_host, assume_via):
        if not self.raw_url:
            return None, None

        parsed = urlparse(self.raw_url)

        if not assume_via and parsed.netloc != via_host:
            return "3rd_party", None

        # This is a link from via of some kind
        if parsed.path == "/":
            return "via_landing_page", None

        sub_resource = self.SUB_RESOURCE_RE.match(parsed.path)
        if sub_resource:
            # This is a little gross, but we've parsed in now, so store it
            self.resource_type = sub_resource.group(1)

            url_type, url = "via_sub_resource", sub_resource.group(2)
        else:
            url_type, url = "via_page", parsed.path

        url, self.parsed = self._clean_url(url)
        return url_type, url

    @classmethod
    def _clean_url(cls, url):
        """Clean up a URL to ensure it's fully qualified."""
        url = url.lstrip("/")

        parsed = urlparse(url)

        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        return url, parsed

    def __str__(self):
        return "<ClassifiedURL (%s %s)\n\teffective=%s\n\traw=%s>" % (
            self.type,
            self.resource_type,
            self.effective_url,
            self.raw_url,
        )
