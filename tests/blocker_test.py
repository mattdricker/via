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
            ("/oe_/http://example.com", "via_sub_resource", "http://example.com"),
        ),
    )
    def test_via_urls(self, url, url_type, effective_url):
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
    def test_referrer_urls(self, url, url_type, effective_url):
        classified = ClassifiedURL(url, via_host="via", assume_via=False)

        assert classified.type == url_type
        assert classified.effective_url == effective_url

    def test_sub_resource_type_extraction(self):
        classified = ClassifiedURL(
            "http://via/oe_/http://example.com", via_host="via", assume_via=False
        )

        assert classified.resource_type == "oe"


class Ref:
    VIA_HOME_PAGE = "http://via/"
    VIA_SUB_RESOURCE = "http://via/oe_/http://example.com/referrer"
    VIA_PAGE = "http://via/http://example.com/referrer"
    EFFECTIVE_URL = "http://example.com/referrer"


class Path:
    VIA_HOME_PAGE = "/"
    VIA_SUB_RESOURCE = "/oe_/http://example.com/path"
    VIA_PAGE = "/http://example.com/path"
    EFFECTIVE_URL = "http://example.com/path"


class TestBlocker:
    @pytest.mark.usefixtures("good_urls")
    @pytest.mark.parametrize(
        "urls,checks",
        (
            (
                # * -> via_landing_page == landing_page
                ("http://irrelevant", Path.VIA_HOME_PAGE),
                (None, None),
            ),
            (
                # None -> via_page == page_to_check
                (None, Path.VIA_PAGE),
                (Path.EFFECTIVE_URL, None),
            ),
            (
                # via_sub_resource -> via_sub_resource == nested_resource
                (Ref.VIA_SUB_RESOURCE, Path.VIA_SUB_RESOURCE),
                (None, Path.EFFECTIVE_URL),
            ),
            (
                # via_page -> * == referrer_check
                (Ref.VIA_PAGE, Path.VIA_PAGE),
                (Ref.EFFECTIVE_URL, Path.EFFECTIVE_URL),
            ),
            (
                # via_sub_resource -> * == referrer_check
                (Ref.VIA_SUB_RESOURCE, Path.VIA_PAGE),
                (Ref.EFFECTIVE_URL, Path.EFFECTIVE_URL),
            ),
            (
                # None -> via_page == page_to_check
                (None, Path.VIA_PAGE),
                (Path.EFFECTIVE_URL, None),
            ),
            (
                # via_landing_page -> via_page == page_to_check
                (Ref.VIA_HOME_PAGE, Path.VIA_PAGE),
                (Path.EFFECTIVE_URL, None),
            ),
            (
                # 3rd_party -> via_page == page_to_check
                ("http://another.example.com", Path.VIA_PAGE),
                (Path.EFFECTIVE_URL, None),
            ),
            # Some wacky things that might happen if something weird was
            # happening or someone was trying to avoid checking
            (
                # 3rd_party -> via_sub_resource == page_to_check
                ("http://another.example.com", Path.VIA_SUB_RESOURCE),
                (Path.EFFECTIVE_URL, None),
            ),
            (
                # None -> via_sub_resource == page_to_check
                (None, Path.VIA_SUB_RESOURCE),
                (Path.EFFECTIVE_URL, None),
            ),
        ),
    )
    def test_it_applies_rules_correctly(self, blocker, CheckmateClient, urls, checks):
        referrer, path = urls
        full_check, partial_check = checks

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
