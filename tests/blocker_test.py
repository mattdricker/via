import pytest
from checkmatelib import CheckmateException
from mock import create_autospec, patch, sentinel

from via.blocker import Blocker


class AnyStringContaining(str):
    def __eq__(self, other):
        return isinstance(other, (str, unicode)) and self in other


class TestBlocker:
    @pytest.mark.usefixtures("good_url")
    def test_it_passes_through_to_app_with_a_good_url(self, blocker):
        environ = {"PATH_INFO": "/http://good.example.com"}

        response = blocker(environ, sentinel.start_response)

        self.assert_pass_through(blocker, environ, response)

    def test_it_passes_through_to_app_when_checkmate_fails(self, blocker):
        environ = {"PATH_INFO": "/http://any.example.com"}
        blocker._checkmate.check_url.side_effect = CheckmateException

        response = blocker(environ, sentinel.start_response)

        self.assert_pass_through(blocker, environ, response)

    def test_it_skips_checking_for_the_root_page(self, blocker):
        environ = {"PATH_INFO": "/"}

        response = blocker(environ, sentinel.start_response)

        blocker._checkmate.assert_not_called()
        self.assert_pass_through(blocker, environ, response)

    @pytest.mark.parametrize(
        "url,expected_url",
        (
            ("https://good.example.com", "https://good.example.com"),
            ("no-schema.example.com", "http://no-schema.example.com"),
        ),
    )
    def test_it_calls_the_blocking_service(self, blocker, url, expected_url):
        blocker({"PATH_INFO": "/%s" % url}, sentinel.start_response)

        blocker._checkmate.check_url.assert_called_once_with(expected_url)

    @pytest.mark.parametrize(
        "reason,content,status_code",
        (
            ("malicious", "Deceptive site ahead", 200),
            ("publisher-blocked", "requested that we disallow access", 451),
            ("anything_else", "cannot be annotated", 200),
        ),
    )
    def test_it_shows_a_block_page(
        self, blocker, reason, content, status_code, Response
    ):
        environ = {"PATH_INFO": "/http://any.example.com"}
        blocker._checkmate.check_url.return_value.reason_codes = [reason]
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
    def good_url(self, CheckmateClient):
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
