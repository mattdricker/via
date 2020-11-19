from __future__ import unicode_literals

import os
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
        url_to_annotate = wsgi.get_path_info(environ)[1:]
        parsed_url = urlparse(url_to_annotate)

        if not parsed_url.scheme:
            url_to_annotate = "http://" + url_to_annotate

        try:
            hits = self._checkmate.check_url(url_to_annotate)
        except CheckmateException as err:
            LOG.warning(
                "Failed to check url against checkmate with error: {}".format(err)
            )
            hits = None

        if hits:
            template_name, status = self.templates.get(
                hits.reason_codes[0], self.templates["other"]
            )

            template = self._jinja_env.get_template(template_name).render(
                url_to_annotate=url_to_annotate
            )
            resp = Response(template, status=status, mimetype="text/html")
            return resp(environ, start_response)

        return self._application(environ, start_response)
