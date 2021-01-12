from __future__ import unicode_literals

import os
import re
from logging import getLogger

from checkmatelib import CheckmateClient, CheckmateException
from functools32 import lru_cache
from jinja2 import Environment, FileSystemLoader
from urlparse import urlparse
from werkzeug import wsgi
from werkzeug.wrappers import BaseResponse as Response

LOG = getLogger(__name__)


class CachingCheckmateClient(object):
    def __init__(self, checker):
        self.checker = checker

    # A TTL cache with a limit would be better here, but these should get
    # flushed out pretty quick by volume with luck. We should cache as _many_
    # of the referrer checks go back to the same URL
    @lru_cache(1024)
    def check_url(self, url_to_check, allow_all):
        return self.checker.check_url(url_to_check, allow_all=allow_all)


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

        self._checkmate = CachingCheckmateClient(CheckmateClient(checkmate_host))

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

        if url_type == "via_landing_page":
            return None, None, "landing_page"

        if ref_type == "via_sub_resource" and url_type == "via_sub_resource":
            # For sub-resources of sub-resources we will assume that the parent
            # has already been checked. Most CDNs and such won't be on our
            # allow list, so only do a partial check on the actual resource
            return None, url, "nested_resource"

        if ref_type in ("via_page", "via_sub_resource"):
            return referrer, url, "referrer_check"

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
        self.parsed = urlparse(raw_url) if raw_url else None

        self.resource_type = None
        self.type, self.effective_url = self._classify(via_host, assume_via)

    def _classify(self, via_host, assume_via):
        if not self.raw_url:
            return None, None

        if not assume_via and self.parsed.netloc != via_host:
            return "3rd_party", None

        # This is a link from via of some kind
        if self.parsed.path == "/":
            return "via_landing_page", None

        sub_resource = self.SUB_RESOURCE_RE.match(self.parsed.path)
        if sub_resource:
            # This is a little gross, but we've parsed in now, so store it
            self.resource_type = sub_resource.group(1)

            return "via_sub_resource", sub_resource.group(2)

        return "via_page", self._clean_url(self.parsed.path)

    @classmethod
    def _clean_url(cls, url):
        """Clean up a URL to ensure it's fully qualified."""
        url = url.lstrip("/")

        parsed_url = urlparse(url)

        if not parsed_url.scheme:
            url = "http://" + url

        return url

    def __str__(self):
        return "<ClassifiedURL (%s %s)\n\teffective=%s\n\traw=%s>" % (
            self.type,
            self.resource_type,
            self.effective_url,
            self.raw_url,
        )
