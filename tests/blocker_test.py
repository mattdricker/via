import pytest
from checkmatelib import CheckmateException
from mock import call, create_autospec, patch, sentinel

from via.blocker import Blocker, ClassifiedURL


class AnyStringContaining(str):
    def __eq__(self, other):
        return isinstance(other, (str, unicode)) and self in other


class TestClassifiedURL:
    @pytest.mark.parametrize(
        "url,url_type,effective_url",
        (
            ("/", "via_landing_page", None),
            ("/http://example.com", "via_page", "http://example.com"),
            ("///example.com", "via_page", "http://example.com"),
            ("/oe_/https://example.com", "via_sub_resource", "https://example.com"),
            ("/if_///example.com", "via_sub_resource", "http://example.com"),
        ),
    )
    def test_it_classifies_via_urls(self, url, url_type, effective_url):
        classified = ClassifiedURL(url, via_host="n/a", assume_via=True)

        assert classified.type == url_type
        assert classified.effective_url == effective_url

    @pytest.mark.parametrize(
        "url,url_type,effective_url",
        (
            ("http://example.com", "3rd_party", None),
            ("http://via/http://example.com", "via_page", "http://example.com"),
            (
                "http://via/oe_/http://example.com",
                "via_sub_resource",
                "http://example.com",
            ),
        ),
    )
    def test_it_classifies_referrer_urls(self, url, url_type, effective_url):
        classified = ClassifiedURL(url, via_host="via", assume_via=False)

        assert classified.type == url_type
        assert classified.effective_url == effective_url

    def test_it_extracts_sub_resource_type(self):
        classified = ClassifiedURL(
            "http://via/oe_/http://example.com", via_host="via", assume_via=False
        )

        assert classified.resource_type == "oe"

    @pytest.mark.parametrize("prefix", ("http://", "//", ""))
    @pytest.mark.parametrize(
        "domain",
        (
            "www.example.com",
            "host",
            "host:1234",
            "102.123.23.19",
            "102.123.23.19:1234",
        ),
    )
    def test_it_gets_the_right_domain_for_via_urls(self, prefix, domain):
        url = "http://via/%s%s" % (prefix, domain)

        classified = ClassifiedURL(url, via_host="via")

        assert classified.parsed.netloc == domain

    @pytest.mark.parametrize(
        "url",
        (
            # We don't parse 3rd party URLs
            "www.example.com",
            # We don't parse the landing page
            "http://via/",
        ),
    )
    def test_it_doesnt_parse_certain_domains(self, url):
        classified = ClassifiedURL(url, via_host="via")

        assert not classified.parsed


class Ref:
    VIA_HOME = "http://via/"
    VIA_SUB_RESOURCE = "http://via/oe_/http://example.com/referrer"
    VIA_PAGE = "http://via/http://example.com/referrer"
    URL = "http://example.com/referrer"


class Path:
    VIA_HOME = "/"
    VIA_SUB_RESOURCE = "/oe_/http://example.com/path"
    VIA_PAGE = "/http://example.com/path"
    URL = "http://example.com/path"


class TestBlocker:
    @pytest.mark.usefixtures("good_urls")
    @pytest.mark.parametrize(
        "referrer,path,full_check,partial_check",
        (
            # RULE: "landing_page"
            # If we are on the landing page, don't check it
            ("http://any", Path.VIA_HOME, None, None),
            # RULE: "page_to_check"
            # If we arrive on a page but didn't come from Via, or came from the
            # Via landing page we should do a full check on that page
            (None, Path.VIA_PAGE, Path.URL, None),
            (None, Path.VIA_SUB_RESOURCE, Path.URL, None),
            (Ref.VIA_HOME, Path.VIA_PAGE, Path.URL, None),
            (Ref.VIA_HOME, Path.VIA_SUB_RESOURCE, Path.URL, None),
            ("http://3rd_party", Path.VIA_PAGE, Path.URL, None),
            # Some wacky things that might happen if something weird was
            # happening or someone was trying to avoid checking
            ("http://3rd_party", Path.VIA_SUB_RESOURCE, Path.URL, None),
            # RULE: "sub_resource_check"
            # If we are on an identified sub-resource on a page, and came from
            # Via page (other than the landing page) then we can assume that
            # page has been checked and do a partial check. Many "via_page"s
            # are actually sub resources in disguise.
            (Ref.VIA_SUB_RESOURCE, Path.VIA_SUB_RESOURCE, None, Path.URL),
            (Ref.VIA_SUB_RESOURCE, Path.VIA_PAGE, None, Path.URL),
            (Ref.VIA_PAGE, Path.VIA_SUB_RESOURCE, None, Path.URL),
            (Ref.VIA_PAGE, Path.VIA_PAGE, None, Path.URL),
        ),
    )
    def test_it_applies_rules_correctly(
        self, blocker, CheckmateClient, referrer, path, full_check, partial_check
    ):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "HTTP_REFERER": referrer,
            "HTTP_HOST": "via",
        }

        blocker(environ, sentinel.start_response)

        calls = []

        if full_check:
            calls.append(call(full_check, allow_all=False))

        if partial_check:
            calls.append(call(partial_check, allow_all=True))

        CheckmateClient.return_value.check_url.assert_has_calls(calls)

    @pytest.mark.usefixtures("good_urls")
    def test_it_passes_through_to_app_with_a_good_url(self, blocker):
        environ = {"PATH_INFO": "/http://good.example.com"}

        response = blocker(environ, sentinel.start_response)

        self.assert_pass_through(blocker, environ, response)

    def test_it_passes_through_to_app_when_checkmate_fails(
        self, blocker, CheckmateClient
    ):
        environ = {"PATH_INFO": "/http://any.example.com"}
        CheckmateClient.return_value.check_url.side_effect = CheckmateException

        response = blocker(environ, sentinel.start_response)

        self.assert_pass_through(blocker, environ, response)

    @pytest.mark.parametrize(
        "reason,content,status_code",
        (
            ("malicious", "Deceptive site ahead", 200),
            ("publisher-blocked", "requested that we disallow annotating", 451),
            ("anything_else", "cannot be annotated", 200),
        ),
    )
    def test_it_shows_a_block_page(
        self, blocker, reason, content, status_code, Response, CheckmateClient
    ):
        environ = {"PATH_INFO": "/http://any.example.com"}
        CheckmateClient.return_value.check_url.return_value.reason_codes = [reason]
        response = blocker(environ, sentinel.start_response)

        Response.assert_called_once_with(
            AnyStringContaining(content), status=status_code, mimetype="text/html"
        )

        resp = Response.return_value
        resp.assert_called_once_with(environ, sentinel.start_response)
        assert response == resp.return_value

    @classmethod
    def assert_pass_through(cls, blocker, environ, response):
        blocker._application.assert_called_once_with(environ, sentinel.start_response)
        assert response == blocker._application.return_value

    @pytest.fixture
    def good_urls(self, CheckmateClient):
        CheckmateClient.return_value.check_url.return_value = None

    @pytest.fixture
    def blocker(self, application):
        return Blocker(application, checkmate_host="http://checkmate.example.com")

    @pytest.fixture
    def application(self):
        def application(environ, start_response):
            """WSGI application signature."""

        return create_autospec(application, spec_set=True)

    @pytest.fixture(autouse=True)
    def CheckmateClient(self):
        with patch("via.blocker.CheckmateClient", spec_set=True) as CheckmateClient:
            yield CheckmateClient

    @pytest.fixture(autouse=True)
    def Response(self):
        with patch("via.blocker.Response", spec_set=True) as Response:
            yield Response
