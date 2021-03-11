from __future__ import unicode_literals

import re
from logging import getLogger

from checkmatelib import CheckmateClient, CheckmateException
from repr import repr
from urlparse import urlparse
from werkzeug import wsgi
from werkzeug.wrappers import BaseResponse as Response

LOG = getLogger(__name__)


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

    def __init__(self, application, checkmate_host, api_key):
        self._application = application
        self._checkmate = CheckmateClient(checkmate_host, api_key)

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

            blocked = self._check_url(url_to_check.proxied_url, allow_all=allow_all)
            if not blocked:
                continue

            response = Response(
                "",
                status="307 Temporary Redirect",
                headers=[("Location", blocked.presentation_url)],
            )
            return response(environ, start_response)

        return self._application(environ, start_response)

    @classmethod
    def _get_urls_to_check(cls, url, referrer):
        """Determine what checks to make based on a URL and referrer.

        Return a tuple of three items:

        1. A URL that should be "fully checked" (checked against both Checkmate's
           allow-list and its block-list).
           This will be one of the given `url` or `referrer`, or `None`
        2. A URL that should be "partially checked" (checked against Checkmate's
           block-list only).
           This will also be one of the given `url` or `referrer`, or `None`
        3. The name of the triggered rule (for debugging)


        :param url: ClassifiedURL instance for the url being served
        :param referrer: ClassifiedURL instance for the referrer
        :return: A tuple of (url_to_fully_check, url_to_partially_check, rule_type)
        """
        # Although we never return anything other than the original URL, the
        # system is written to be flexible enough to return the referrer
        # instead or both if we want to. This is to allow future tweaks to the
        # ruleset without major refactoring.

        if url.type == ClassifiedURL.Type.VIA_LANDING_PAGE:
            return None, None, "landing_page"

        if referrer.type in (
            ClassifiedURL.Type.VIA_PAGE,
            ClassifiedURL.Type.VIA_SUB_RESOURCE,
        ):
            return None, url, "sub_resource_check"

        return url, None, "page_to_check"

    def _check_url(self, url, allow_all=False):
        """Check a URL with checkmate."""

        try:
            return self._checkmate.check_url(url, allow_all=allow_all)

        except CheckmateException as err:
            LOG.exception(
                "Failed to check url against checkmate with error: {}".format(err)
            )
            return None


class ClassifiedURL(object):
    """A URL with extra information about it's source."""

    class Type(object):
        # The URL isn't from Via at all
        THIRD_PARTY = "3rd_party"
        # The URL is the Via landing page
        VIA_LANDING_PAGE = "via_landing_page"
        # The URL is a Via sub-resource served from a page
        VIA_SUB_RESOURCE = "via_sub_resource"
        # The URL is a Via proxied root page, or indistinguishable from one
        VIA_PAGE = "via_page"

    def __init__(self, type_, raw_url, proxied_url=None, resource_type=None):
        """Create a URL with metadata.

        :param type_: The classification of the URL (from ClassifiedURL.Type)
            or None
        :param raw_url: The original raw URL
        :param proxied_url: If this is a Via proxy, the proxied site
        :param resource_type: If this is a VIA_SUB_RESOURCE the resource type
        """
        self.raw_url = raw_url
        self.type = type_

        if proxied_url:
            self.proxied_url, self.proxied_domain = self._clean_url(proxied_url)
        else:
            self.proxied_url, self.proxied_domain = None, None

        if type_ != self.Type.VIA_SUB_RESOURCE:
            assert resource_type is None

        self.resource_type = resource_type

    @classmethod
    def _clean_url(cls, url):
        """Clean up a URL to ensure it's fully qualified."""
        url = url.lstrip("/")

        parsed = urlparse(url)

        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        return url, parsed.netloc

    SUB_RESOURCE_RE = re.compile(r"^/([a-z]{2})_/(.*)$")

    @classmethod
    def classify(cls, raw_url, via_host, assume_via=False):
        if not raw_url:
            # This happens when the Referer header is missing.
            return cls(None, raw_url)

        parsed = urlparse(raw_url)

        if not assume_via and parsed.netloc != via_host:
            # This happens when the URL in the Referer header is to a site other than Via.
            return cls(cls.Type.THIRD_PARTY, raw_url)

        if parsed.path == "/":
            # A request to Via's landing page.
            return cls(cls.Type.VIA_LANDING_PAGE, raw_url)

        sub_resource = cls.SUB_RESOURCE_RE.match(parsed.path)
        if sub_resource:
            # A request for a sub-resource of a proxied page.
            return cls(
                cls.Type.VIA_SUB_RESOURCE,
                raw_url,
                resource_type=sub_resource.group(1),
                proxied_url=sub_resource.group(2),
            )

        # A top level request to proxy a page or a sub-resource that looks
        # identical to one
        return ClassifiedURL(cls.Type.VIA_PAGE, raw_url, proxied_url=parsed.path)

    def __repr__(self):
        return "%s(%s, %s, %s, %s)" % (
            self.__class__.__name__,
            repr(self.type),
            self.raw_url,
            self.proxied_url,
            repr(self.resource_type),
        )
