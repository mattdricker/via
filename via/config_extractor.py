from __future__ import unicode_literals

import logging
from urllib import urlencode

from urlparse import parse_qsl, urlparse, urlunparse

from via.configuration import Configuration


def rewrite_location_header(name, value, params):
    """
    Rewrite "Location" header to append params to the URL's query string.

    Returns other headers unmodified.

    :param name: HTTP header name
    :param value: HTTP header value
    :param params: dict of params to add to the URL's query string
    :return: Modified (name, value) pair
    """

    if name.lower() != "location":
        return (name, value)

    try:
        parsed_url = urlparse(value)
        parsed_query = parse_qsl(parsed_url.query, keep_blank_values=True)

        for k, v in params.items():
            parsed_query.append((k, v))

        updated_query = urlencode(parsed_query)
        updated_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                updated_query,
                parsed_url.fragment,
            )
        )

        return (name, updated_url)
    except Exception:
        logging.warn('Failed to parse "Location" header: {}'.format(value))
        return (name, value)


def pop_query_params_with_prefix(environ, prefix):
    """
    Extract and remove query string parameters beginning with ``prefix``.

    :param environ: WSGI environ dict
    :param prefix: Prefix to match
    :return: A dict of query param / value pairs
    """
    orig_qs = environ["QUERY_STRING"]
    parsed_query_items = parse_qsl(orig_qs, keep_blank_values=True)
    popped_params = {}
    updated_query_items = []

    for key, value in parsed_query_items:
        if key.startswith(prefix):
            popped_params[key] = value
        else:
            updated_query_items.append((key, value))

    updated_qs = urlencode(updated_query_items)
    environ["QUERY_STRING"] = updated_qs

    if "REQUEST_URI" in environ:
        # If using uwsgi, update `REQUEST_URI`.
        environ["REQUEST_URI"] = environ["REQUEST_URI"][: -len(orig_qs)] + updated_qs

    return popped_params


class ConfigExtractor(object):
    """
    WSGI middleware which extracts client configuration params from the URL.

    Client configuration is supplied via "via."-prefixed query parameters,
    which are removed from the URL passed along to the proxy server.

    These parameters are then used to populate the parameters exposed to
    rendered templates.

    This middleware also rewrites redirect responses from the upstream app to
    preserve "via."-prefixed parameters from the original request. Note that
    this only works for server-side redirects. Client-side redirects will still
    "lose" these parameters.
    """

    def __init__(self, application):
        self._application = application

    def __call__(self, environ, start_response):
        client_params = self._make_hypothesis_client_config(environ)

        via_params = pop_query_params_with_prefix(environ, "via.")

        template_params = environ.get("pywb.template_params", {})
        template_params["hypothesis_config"] = client_params

        if "via.features" in via_params:
            template_params["via_features"] = via_params["via.features"].split(",")

        external_link_mode = via_params.get("via.external_link_mode")
        if external_link_mode not in ["same-tab", "new-tab"]:
            external_link_mode = "same-tab"
        template_params["external_link_mode"] = external_link_mode

        environ["pywb.template_params"] = template_params

        # A wrapper which intercepts redirects and adds any params from `via_params`
        # to the query string in the URL in the "Location" header.
        #
        # This ensures that client configuration is preserved if the user requests
        # a URL which immediately redirects.
        def start_response_wrapper(status, headers, exc_info=None):
            code_str, _ = status.split(" ", 1)
            code = int(code_str)

            if code >= 300 and code < 400:
                headers = [
                    rewrite_location_header(k, v, via_params) for k, v in headers
                ]

            return start_response(status, headers, exc_info)

        return self._application(environ, start_response_wrapper)

    def _make_hypothesis_client_config(self, environ):
        # Convert from keys being lists to being dict values. We don't expect
        # duplicates for our values, so it's ok to overwrite
        params = dict(parse_qsl(environ["QUERY_STRING"], keep_blank_values=True))

        _, client_params = Configuration.extract_from_params(params)

        return client_params
