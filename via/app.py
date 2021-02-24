import logging
import os

import newrelic.agent
import pywb.apps.wayback
from pkg_resources import resource_filename
from werkzeug import wsgi
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect
from werkzeug.wrappers import Request, Response

import static
from via.blocker import Blocker
from via.config_extractor import ConfigExtractor
from via.security import RequestHeaderSanitiser, ResponseHeaderSanitiser
from via.useragent import UserAgentDecorator

logging.disable(logging.INFO)


# Previously, PDFs were served at paths like
#
#     /static/__shared/viewer/web/viewer.html?file=http://example.com/test.pdf
#
# We can now serve them directly as
#
#     /http://example.com/test.pdf
#
# So we redirect from the old-style paths to new ones.
@wsgi.responder
def redirect_old_viewer(environ, start_response):
    request = Request(environ)
    if "file" not in request.args:
        return NotFound()
    uri = request.args["file"]
    if uri.startswith("/id_/"):
        uri = uri[len("/id_/") :]
    return redirect("/{0}".format(uri))


# Can be used as a handler at any path to redirect to the root with the matched
# path stripped. For example, mounting this app at '/foo' will mean that
# requests are redirected as follows:
#
#     /foo                    -> /
#     /foo/bar                -> /bar
#     /foo/bar?baz            -> /bar?baz
#     /foo/http://example.com -> /http://example.com
#
# and so on.
@wsgi.responder
def redirect_strip_matched_path(environ, start_response):
    request = Request(environ)
    path = request.path
    if request.query_string:
        path += "?" + request.query_string
    return redirect(path, code=301)


def status_endpoint(environ, start_response):
    response = Response('{"status": "okay"}', status=200, mimetype="application/json")

    return response(environ, start_response)


def app(environ, start_response):
    embed_url = os.environ.get("H_EMBED_URL", "https://hypothes.is/embed.js")

    template_params = environ.get("pywb.template_params", {})
    template_params["h_embed_url"] = embed_url
    environ["pywb.template_params"] = template_params

    return pywb.apps.wayback.application(environ, start_response)


application = RequestHeaderSanitiser(app)
application = ResponseHeaderSanitiser(application)
application = Blocker(
    application,
    checkmate_host=os.environ["CHECKMATE_URL"],
    api_key=os.environ["CHECKMATE_API_KEY"],
)
application = UserAgentDecorator(application, "Hypothesis-Via")
application = ConfigExtractor(application)
application = wsgi.DispatcherMiddleware(
    application,
    {
        "/favicon.ico": static.Cling("static/favicon.ico"),
        "/robots.txt": static.Cling("static/robots.txt"),
        "/static": static.Cling("static/"),
        "/static/__pywb": static.Cling(resource_filename("pywb", "static/")),
        "/static/__shared/viewer/web/viewer.html": redirect_old_viewer,
        "/h": redirect_strip_matched_path,
        "/_status": status_endpoint,
    },
)
application = newrelic.agent.WSGIApplicationWrapper(application, name="proxy")
