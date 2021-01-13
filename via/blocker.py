from __future__ import unicode_literals

import os
import re
from logging import getLogger

from checkmatelib import CheckmateClient, CheckmateException
from jinja2 import Environment, FileSystemLoader
from repr import repr
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
        classified_url = ClassifiedURL.classify(request_path, via_host, assume_via=True)
        classified_referrer = ClassifiedURL.classify(
            environ.get("HTTP_REFERER"), via_host
        )

        # Determine which urls should be run against checkmate (if any)
        full_check, partial_check, rule_type = self._get_urls_to_check(
            classified_url, classified_referrer
        )

        # Apply the checks
        for url_to_check, allow_all in ((full_check, False), (partial_check, True)):
            if not url_to_check:
                # No check of this type requested
                continue

            hits = self._check_url(url_to_check.effective_url, allow_all=allow_all)
            if not hits:
                continue

            response = self._render_block_template(hits, url_to_check)
            return response(environ, start_response)

        return self._application(environ, start_response)

    @classmethod
    def _get_urls_to_check(cls, url, referrer):
        """Determine what checks to make based on a URL and referrer.

        This will return up to two of the passed in ClassifiedURL objects. The
        first of which should have a full allow list enabled check. The second
        should get a partial allow list disabled check.

        The third item is the name of the triggered rule (purely for debugging)

        :param url: ClassifiedURL instance for the url being served
        :param referrer: ClassifiedURL instance for the referrer
        :return: A tuple of (full_check_url, partial_check_url, rule_type)
        """
        # Although we never return anything other than the original URL, the
        # system is written to be flexible enough to return the referrer
        # instead or both if we want to. This is to allow future tweaks to the
        # ruleset without major refactoring.

        if url.type == "via_landing_page":
            return None, None, "landing_page"

        if referrer.type in ("via_page", "via_sub_resource"):
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

    def __init__(self, type_, raw_url, effective_url=None, resource_type=None):
        """Create a URL with metadata.

        :param type_: The classification of the URL
        :param raw_url: The original raw URL
        :param effective_url: If this is a Via proxy, the proxied site
        :param resource_type: If this is a "sub_resource" the resource type
        """
        self.raw_url = raw_url
        self.type = type_

        if effective_url:
            self.effective_url, self.parsed = self._clean_url(effective_url)
        else:
            self.effective_url, self.parsed = None, None

        if self.type == "via_sub_resource":
            self.resource_type = resource_type
        else:
            self.resource_type = None

    @classmethod
    def _clean_url(cls, url):
        """Clean up a URL to ensure it's fully qualified."""
        url = url.lstrip("/")

        parsed = urlparse(url)

        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        return url, parsed

    @classmethod
    def classify(cls, raw_url, via_host, assume_via=False):
        if not raw_url:
            # Safety valve for being passed nonsense
            return ClassifiedURL(None, raw_url)

        parsed = urlparse(raw_url)

        if not assume_via and parsed.netloc != via_host:
            # A site other than Via
            return ClassifiedURL("3rd_party", raw_url)

        if parsed.path == "/":
            # A request to Via's landing page
            return ClassifiedURL("via_landing_page", raw_url)

        sub_resource = cls.SUB_RESOURCE_RE.match(parsed.path)
        if sub_resource:
            # A request for a sub-resource of a proxied page.
            return ClassifiedURL(
                "via_sub_resource",
                raw_url,
                resource_type=sub_resource.group(1),
                effective_url=sub_resource.group(2),
            )

        # A top level request to proxy a page or a sub-resource that looks
        # identical to one
        return ClassifiedURL("via_page", raw_url, effective_url=parsed.path)

    def __repr__(self):
        return "%s(%s, %s, %s, %s)" % (
            self.__class__.__name__,
            repr(self.type),
            self.raw_url,
            self.effective_url,
            repr(self.resource_type),
        )
