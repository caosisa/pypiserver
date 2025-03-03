import logging
import mimetypes
import os
import re
import xml.dom.minidom
import xmlrpc.client as xmlrpclib
import zipfile
import re
import requests
from functools import lru_cache
from collections import defaultdict
from collections import namedtuple
from io import BytesIO
from json import dumps
from urllib.parse import urljoin, urlparse, quote

from pypiserver.config import RunConfig
from . import __version__
from .bottle import (
    static_file,
    redirect,
    request,
    response,
    HTTPError,
    Bottle,
    template,
)
from .pkg_helpers import guess_pkgname_and_version, normalize_pkgname_for_url

log = logging.getLogger(__name__)
config: RunConfig
app = Bottle()


def request_fullpath(request):
    parsed = urlparse(request.urlparts.scheme + "://" + request.urlparts.netloc)
    return parsed.path.rstrip("/") + "/" + request.fullpath.lstrip("/")


def get_bad_url_redirect_path(request, project):
    """Get the path for a bad root url."""
    uri = request_fullpath(request)
    if uri.endswith("/"):
        uri = uri[:-1]
    uri = uri.rsplit("/", 1)[0]
    project = quote(project)
    uri += f"/simple/{project}/"
    return uri


class auth:
    """decorator to apply authentication if specified for the decorated method & action"""

    def __init__(self, action):
        self.action = action

    def __call__(self, method):
        def protector(*args, **kwargs):
            if self.action in config.authenticate:
                if not request.auth or request.auth[1] is None:
                    raise HTTPError(
                        401, headers={"WWW-Authenticate": 'Basic realm="pypi"'}
                    )
                if not config.auther(*request.auth):
                    raise HTTPError(403)
            return method(*args, **kwargs)

        return protector


@
@lru_cache(maxsize=1024)
def is_valid_pypi_package(package_name, version=None):
    """
    Validates if a package exists on PyPI and optionally if the specific version exists.
    Uses caching to reduce API calls.
    """
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
        if response.status_code != 200:
            return False
        
        if version is None:
            return True
            
        data = response.json()
        return version in data["releases"]
    except Exception:
        # On any error, fail closed
        return False

def get_client_os():
    """Extract client OS from User-Agent header"""
    user_agent = request.headers.get('User-Agent', '').lower()
    
    if 'android' in user_agent:
        return 'android'
    elif any(ios_marker in user_agent for ios_marker in ['iphone', 'ipad', 'ipod', 'ios']):
        return 'ios'
    else:
        return 'unknown'

@app.hook('before_request')
def validate_request():
    # Skip validation for certain paths like static assets
    path = request.path
    
    # Exempt certain paths like favicon, static assets, etc.
    if path in ['/favicon.ico']:
        return
        
    # 1. OS Validation
    client_os = get_client_os()
    if client_os not in ['android', 'ios']:
        log.warning(f"Blocked request from unsupported OS: {client_os}")
        raise HTTPError(403, "Only Android and iOS clients are supported")
    
    # 2. Package validation for relevant paths
    if '/simple/' in path and len(path.split('/simple/')) > 1:
        # Extract package name from URL (handles /simple/package/ paths)
        parts = path.split('/simple/')
        if len(parts) > 1:
            package_parts = parts[1].strip('/').split('/')
            package_name = package_parts[0]
            
            if not is_valid_pypi_package(package_name):
                log.warning(f"Blocked request for unofficial package: {package_name}")
                raise HTTPError(404, f"Package {package_name} is not available in official PyPI")
    
    # 3. Block git+ and other non-standard installs
    # This would typically happen during the package resolution/download phase
    if '/packages/' in path:
        filename = path.split('/packages/')[1]
        
        # Block git+ and other non-standard formats
        if '+' in filename or filename.startswith('git-'):
            log.warning(f"Blocked request for non-standard package source: {filename}")
            raise HTTPError(403, "Non-standard package sources are not supported")
        
        # If it's a package file, validate it exists in PyPI
        pkg_info = guess_pkgname_and_version(filename)
        if pkg_info:
            pkg_name, pkg_version = pkg_info
            if not is_valid_pypi_package(pkg_name, pkg_version):
                log.warning(f"Blocked request for unofficial package version: {pkg_name}=={pkg_version}")
                raise HTTPError(404, f"Package {pkg_name}=={pkg_version} is not available in official PyPI")

@app.hook("after_request")
def log_response():
    log.info(
        config.log_res_frmt,
        {  # vars(response))  ## DOES NOT WORK!
            "response": response,
            "status": response.status,
            "headers": response.headers,
            "body": response.body,
            "cookies": response._cookies,
        },
    )


@app.error
def log_error(http_error):
    log.info(config.log_err_frmt, vars(http_error))


@app.route("/favicon.ico")
def favicon():
    return HTTPError(404)


@app.route("/")
def root():
    parsed = urlparse(request.urlparts.scheme + "://" + request.urlparts.netloc)
    fp = parsed.path.rstrip("/") + "/" + request.fullpath.lstrip("/")

    # Ensure template() does not consider `msg` as filename!
    msg = config.welcome_msg + "\n"
    return template(
        msg,
        URL=request.url.rstrip("/") + "/",
        VERSION=__version__,
        NUMPKGS=config.backend.package_count(),
        PACKAGES=fp.rstrip("/") + "/packages/",
        SIMPLE=fp.rstrip("/") + "/simple/",
    )


_bottle_upload_filename_re = re.compile(r"^[a-z0-9_.!+-]+$", re.I)


def is_valid_pkg_filename(fname):
    """See https://github.com/pypiserver/pypiserver/issues/102"""
    return _bottle_upload_filename_re.match(fname) is not None


def doc_upload():
    try:
        content = request.files["content"]
    except KeyError:
        raise HTTPError(400, "Missing 'content' file-field!")
    zip_data = content.file.read()
    try:
        zf = zipfile.ZipFile(BytesIO(zip_data))
        zf.getinfo("index.html")
    except Exception:
        raise HTTPError(400, "not a zip file")


def remove_pkg():
    name = request.forms.get("name")
    version = request.forms.get("version")
    if not name or not version:
        msg = f"Missing 'name'/'version' fields: name={name}, version={version}"
        raise HTTPError(400, msg)

    pkgs = list(config.backend.find_version(name, version))
    if not pkgs:
        raise HTTPError(404, f"{name} ({version}) not found")
    for pkg in pkgs:
        config.backend.remove_package(pkg)


Upload = namedtuple("Upload", "pkg sig")


def file_upload():
    ufiles = Upload._make(
        request.files.get(f, None) for f in ("content", "gpg_signature")
    )
    if not ufiles.pkg:
        raise HTTPError(400, "Missing 'content' file-field!")
    if (
        ufiles.sig
        and f"{ufiles.pkg.raw_filename}.asc" != ufiles.sig.raw_filename
    ):
        raise HTTPError(
            400,
            f"Unrelated signature {ufiles.sig!r} for package {ufiles.pkg!r}!",
        )

    for uf in ufiles:
        if not uf:
            continue
        if (
            not is_valid_pkg_filename(uf.raw_filename)
            or guess_pkgname_and_version(uf.raw_filename) is None
        ):
            raise HTTPError(400, f"Bad filename: {uf.raw_filename}")

        if not config.overwrite and config.backend.exists(uf.raw_filename):
            log.warning(
                f"Cannot upload {uf.raw_filename!r} since it already exists! \n"
                "  You may start server with `--overwrite` option. "
            )
            raise HTTPError(
                409,
                f"Package {uf.raw_filename!r} already exists!\n"
                "  You may start server with `--overwrite` option.",
            )

        config.backend.add_package(uf.raw_filename, uf.file)
        if request.auth:
            user = request.auth[0]
        else:
            user = "anon"
        log.info(f"User {user!r} stored {uf.raw_filename!r}.")


@app.post("/")
@auth("update")
def update():
    try:
        action = request.forms[":action"]
    except KeyError:
        raise HTTPError(400, "Missing ':action' field!")

    if action in ("verify", "submit"):
        log.warning(f"Ignored ':action': {action}")
    elif action == "doc_upload":
        doc_upload()
    elif action == "remove_pkg":
        remove_pkg()
    elif action == "file_upload":
        file_upload()
    else:
        raise HTTPError(400, f"Unsupported ':action' field: {action}")

    return ""


@app.route("/simple")
@app.route("/simple/:project")
@app.route("/packages")
@auth("list")
def pep_503_redirects(project=None):
    return redirect(request_fullpath(request) + "/", 301)


@app.post("/RPC2")
@auth("list")
def handle_rpc():
    """Handle pip-style RPC2 search requests"""
    parser = xml.dom.minidom.parse(request.body)
    methodname = (
        parser.getElementsByTagName("methodName")[0]
        .childNodes[0]
        .wholeText.strip()
    )
    log.debug(f"Processing RPC2 request for '{methodname}'")
    if methodname == "search":
        value = (
            parser.getElementsByTagName("string")[0]
            .childNodes[0]
            .wholeText.strip()
        )
        response = []
        ordering = 0
        for p in config.backend.get_all_packages():
            if p.pkgname.count(value) > 0:
                # We do not presently have any description/summary, returning
                # version instead
                d = {
                    "_pypi_ordering": ordering,
                    "version": p.version,
                    "name": p.pkgname,
                    "summary": p.version,
                }
                response.append(d)
            ordering += 1
        call_string = xmlrpclib.dumps(
            (response,), "search", methodresponse=True
        )
        return call_string


@app.route("/simple/")
@auth("list")
def simpleindex():
    links = sorted(config.backend.get_projects())
    tmpl = """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Simple Index</title>
    </head>
    <body>
        <h1>Simple Index</h1>
        % for p in links:
                <a href="{{p}}/">{{p}}</a><br>
        % end
    </body>
</html>
    """
    return template(tmpl, links=links)


@app.route("/simple/:project/")
@auth("list")
def simple(project):
    # PEP 503: require normalized project
    normalized = normalize_pkgname_for_url(project)
    if project != normalized:
        return redirect(f"/simple/{normalized}/", 301)

    packages = sorted(
        config.backend.find_project_packages(project),
        key=lambda x: (x.parsed_version, x.relfn),
    )
    if not packages:
        if not config.disable_fallback:
            return redirect(f"{config.fallback_url.rstrip('/')}/{project}/")
        return HTTPError(404, f"Not Found ({normalized} does not exist)\n\n")

    current_uri = request_fullpath(request)

    links = (
        (
            os.path.basename(pkg.relfn),
            urljoin(current_uri, f"../../packages/{pkg.fname_and_hash}"),
        )
        for pkg in packages
    )

    tmpl = """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Links for {{project}}</title>
    </head>
    <body>
        <h1>Links for {{project}}</h1>
        % for file, href in links:
            <a href="{{href}}">{{file}}</a><br>
        % end
    </body>
</html>
    """
    return template(tmpl, project=project, links=links)


@app.route("/packages/")
@auth("list")
def list_packages():
    fp = request_fullpath(request)
    packages = sorted(
        config.backend.get_all_packages(),
        key=lambda x: (os.path.dirname(x.relfn), x.pkgname, x.parsed_version),
    )

    links = (
        (pkg.relfn_unix, urljoin(fp, pkg.fname_and_hash)) for pkg in packages
    )

    tmpl = """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Index of packages</title>
    </head>
    <body>
        <h1>Index of packages</h1>
        % for file, href in links:
            <a href="{{href}}">{{file}}</a><br>
        % end
    </body>
</html>
    """
    return template(tmpl, links=links)


@app.route("/packages/:filename#.*#")
@auth("download")
def server_static(filename):
    entries = config.backend.get_all_packages()
    for x in entries:
        f = x.relfn_unix
        if f == filename:
            response = static_file(
                filename,
                root=x.root,
                mimetype=mimetypes.guess_type(filename)[0],
            )
            if config.cache_control:
                response.set_header(
                    "Cache-Control", f"public, max-age={config.cache_control}"
                )
            return response

    return HTTPError(404, f"Not Found ({filename} does not exist)\n\n")


@app.route("/:project/json")
@auth("list")
def json_info(project):
    # PEP 503: require normalized project
    normalized = normalize_pkgname_for_url(project)
    if project != normalized:
        return redirect(f"/{normalized}/json", 301)

    packages = sorted(
        config.backend.find_project_packages(project),
        key=lambda x: x.parsed_version,
        reverse=True,
    )

    if not packages:
        raise HTTPError(404, f"package {project} not found")

    latest_version = packages[0].version
    releases = defaultdict(list)
    req_url = request.url
    for x in packages:
        releases[x.version].append(
            {"url": urljoin(req_url, "../../packages/" + x.relfn)}
        )

    rv = {"info": {"version": latest_version}, "releases": releases}
    response.content_type = "application/json"
    return dumps(rv)


@app.route("/:project")
@app.route("/:project/")
def bad_url(project):
    """Redirect unknown root URLs to /simple/."""
    return redirect(get_bad_url_redirect_path(request, project))
