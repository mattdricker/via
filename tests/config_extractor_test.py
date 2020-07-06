from __future__ import unicode_literals

import json

import pytest
import urlparse
from werkzeug import wsgi
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse as Response

from via.config_extractor import (
    ConfigExtractor,
    pop_query_params_with_prefix,
    rewrite_location_header,
)

DEFAULT_CONTENT_TYPE = ("Content-Type", "text/html")


class TestPopQueryParamsWithPrefix(object):
    def test_it_ignores_non_matching_params(self, create_environ):
        environ = create_environ("one=1&two=2&three=3")
        orig_envion = environ.copy()

        params = pop_query_params_with_prefix(environ, "aprefix.")

        assert params == {}
        assert environ == orig_envion

    def test_it_pops_matching_params(self, create_environ):
        environ = create_environ("one=1&two=2&aprefix.three=3&four=4")

        params = pop_query_params_with_prefix(environ, "aprefix.")

        expected_environ = create_environ("one=1&two=2&four=4")
        assert params == {"aprefix.three": "3"}
        assert environ == expected_environ

    @pytest.fixture
    def create_environ(self):
        def create(query_string):
            return {
                "QUERY_STRING": query_string,
                "REQUEST_URI": "http://example.com?{}".format(query_string),
            }

        return create


class TestRewriteLocationHeader(object):
    def test_it_ignores_non_location_headers(self):
        params = {"via.foo": "bar", "via.baz": "meep"}

        header, value = rewrite_location_header(
            "Not-Location", "https://example.com", params
        )

        assert header == "Not-Location"
        assert value == "https://example.com"

    @pytest.mark.parametrize("header_name", [("location"), ("Location"), ("LOCATION")])
    def test_it_adds_params_to_location_header(self, header_name):
        params = {"via.foo": "bar", "via.baz": "meep"}

        header, value = rewrite_location_header(
            header_name, "https://example.com", params
        )
        parsed_value = urlparse.urlparse(value)
        parsed_qs = urlparse.parse_qs(parsed_value.query)

        assert header == header_name
        assert value.startswith("https://example.com?")
        assert parsed_qs == {"via.foo": ["bar"], "via.baz": ["meep"]}

    def test_it_preserves_rest_of_url_in_location_header(self):
        query_string = "empty_param=&non_empty_param=foo&q=one&q=two"
        url = "https://localhost:5000/a/path?{}#some_fragment".format(query_string)

        header, value = rewrite_location_header("Location", url, {})

        assert header == "Location"
        assert value == url

    def test_it_returns_original_header_if_url_cannot_be_parsed(self):
        url = "http://["

        header, value = rewrite_location_header("Location", url, {"via.foo": "bar"})

        assert header == "Location"
        assert value == url


class TestConfigExtractor(object):
    def test_it_sets_template_params_from_matching_query_params(self, client_get):
        resp = client_get(
            "/example.com?q=foobar&"
            "via.client.openSidebar=1&"
            "via.client.requestConfigFromFrame.origin=https://lms.hypothes.is&"
            "via.client.requestConfigFromFrame.ancestorLevel=3"
        )

        template_params = json.loads(resp.data).get("pywb.template_params")
        assert template_params == {
            "hypothesis_config": {
                "appType": "via",
                "openSidebar": "1",
                "requestConfigFromFrame": {
                    "origin": "https://lms.hypothes.is",
                    "ancestorLevel": "3",
                },
                "showHighlights": True,
            },
            "external_link_mode": "same-tab",
        }

    @pytest.mark.parametrize(
        "query_param_value,expected_mode",
        [
            ("", "same-tab"),
            ("same-tab", "same-tab"),
            ("new-tab", "new-tab"),
            ("invalid", "same-tab"),
        ],
    )
    def test_it_sets_external_link_mode_template_param(
        self, client_get, query_param_value, expected_mode
    ):
        resp = client_get(
            "/example.com?q=foobar&via.external_link_mode=" + query_param_value
        )
        template_params = json.loads(resp.data).get("pywb.template_params")
        assert template_params["external_link_mode"] == expected_mode

    def test_it_sets_via_features_template_param(self, client_get):
        resp = client_get("/example.com?q=foobar&" "via.features=feature_a,feature_b")

        template_params = json.loads(resp.data).get("pywb.template_params")
        assert template_params["via_features"] == ["feature_a", "feature_b"]

    def test_it_passes_non_matching_query_params_to_upstream_app(self, client_get):
        resp = client_get("/example.com?q=foobar&via.client.openSidebar=1")

        upstream_environ = json.loads(resp.data)
        assert upstream_environ["QUERY_STRING"] == "q=foobar"
        assert upstream_environ["REQUEST_URI"] == "/example.com?q=foobar"

    @pytest.mark.parametrize(
        "upstream_status,upstream_location",
        [
            ("302 Found", "https://example.com/moved"),
            ("301 Moved Permanently", "https://example.com/moved"),
        ],
    )
    def test_it_propagates_matching_query_params_to_redirect_location(
        self, client_get, upstream_status, upstream_location
    ):
        def upstream_app(environ, start_response):
            start_response(upstream_status, [("Location", upstream_location)])
            return []

        request_url = "/example.com/old-path?q=foobar&via.client.openSidebar=1"

        resp = client_get(request_url, ConfigExtractor(upstream_app))

        assert resp.status == upstream_status
        assert (
            resp.headers.get("Location")
            == "https://example.com/moved?via.client.openSidebar=1"
        )

    @pytest.mark.parametrize(
        "upstream_status,upstream_headers",
        [
            # nb. A default "Content-Type" header gets inserted if none is supplied
            # by upstream, so all examples here include one.
            ("200 OK", [DEFAULT_CONTENT_TYPE]),
            # 201 responses include a "Location" header, but browsers don't redirect
            # to the created resource.
            (
                "201 Created",
                [DEFAULT_CONTENT_TYPE, ("Location", "https://dont_touch_me.com/")],
            ),
            ("400 Bad Request", [DEFAULT_CONTENT_TYPE]),
        ],
    )
    def test_it_returns_response_unmodified_if_upstream_returns_non_3xx_status(
        self, client_get, upstream_status, upstream_headers
    ):
        upstream_body = "Content from upstream"

        def upstream_app(environ, start_response):
            start_response(upstream_status, upstream_headers)
            return upstream_body

        request_url = "/example.com/a_path?q=foobar&via.client.openSidebar=1"

        resp = client_get(request_url, ConfigExtractor(upstream_app))

        assert resp.data == upstream_body
        assert resp.status == upstream_status
        assert resp.headers.items() == upstream_headers

    @pytest.fixture
    def app(self):
        return ConfigExtractor(upstream_app)

    @pytest.fixture
    def client_get(self, app):
        def get(url, upstream_app=app):
            client = Client(upstream_app, Response)

            # `Client` does not set "REQUEST_URI" as this is set by uwsgi in
            # the actual app. Set it manually here.
            environ = {"REQUEST_URI": url}

            return client.get(url, environ_overrides=environ)

        return get


@wsgi.responder
def upstream_app(environ, start_response):
    class Encoder(json.JSONEncoder):
        def default(self, o):
            try:
                return json.JSONEncoder.default(self, o)
            except TypeError:
                # Ignore un-serializable fields.
                return None

    body = Encoder().encode(environ)
    return Response(body)
