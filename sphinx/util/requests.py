"""Simple requests package loader"""

import sys
import warnings
from contextlib import contextmanager
from typing import Any, Generator, Union
from urllib.parse import urlsplit
from os import path

import requests
from urllib3.exceptions import InsecureRequestWarning
from http.cookiejar import MozillaCookieJar

import sphinx
from sphinx.config import Config

cookie_dir = path.expanduser("~/.midway")
cookie_file = path.join(cookie_dir, "cookie")

if path.isfile(cookie_file):
    cookie_jar = MozillaCookieJar()
    cookie_jar.load(cookie_file)

useragent_header = [('User-Agent',
                     'Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0')]


@contextmanager
def ignore_insecure_warning(**kwargs: Any) -> Generator[None, None, None]:
    with warnings.catch_warnings():
        if not kwargs.get('verify') and InsecureRequestWarning:
            # ignore InsecureRequestWarning if verify=False
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        yield


def _get_tls_cacert(url: str, config: Config) -> Union[str, bool]:
    """Get additional CA cert for a specific URL.

    This also returns ``False`` if verification is disabled.
    And returns ``True`` if additional CA cert not found.
    """
    if not config.tls_verify:
        return False

    certs = getattr(config, 'tls_cacerts', None)
    if not certs:
        return True
    elif isinstance(certs, (str, tuple)):
        return certs  # type: ignore
    else:
        hostname = urlsplit(url)[1]
        if '@' in hostname:
            hostname = hostname.split('@')[1]

        return certs.get(hostname, True)


def _get_user_agent(config: Config) -> str:
    if config.user_agent:
        return config.user_agent
    else:
        return ' '.join([
            'Sphinx/%s' % sphinx.__version__,
            'requests/%s' % requests.__version__,
            'python/%s' % '.'.join(map(str, sys.version_info[:3])),
        ])


def get(url: str, **kwargs: Any) -> requests.Response:
    """Sends a GET request like requests.get().

    This sets up User-Agent header and TLS verification automatically."""
    headers = kwargs.setdefault('headers', {})
    config = kwargs.pop('config', None)
    if config:
        kwargs.setdefault('verify', _get_tls_cacert(url, config))
        headers.setdefault('User-Agent', _get_user_agent(config))
    else:
        headers.setdefault('User-Agent', useragent_header[0][1])
    if cookie_jar:
        kwargs.setdefault('cookies', cookie_jar)

    with ignore_insecure_warning(**kwargs):
        return requests.get(url, **kwargs)


def head(url: str, **kwargs: Any) -> requests.Response:
    """Sends a HEAD request like requests.head().

    This sets up User-Agent header and TLS verification automatically."""
    headers = kwargs.setdefault('headers', {})
    config = kwargs.pop('config', None)
    if config:
        kwargs.setdefault('verify', _get_tls_cacert(url, config))
        headers.setdefault('User-Agent', _get_user_agent(config))
    else:
        headers.setdefault('User-Agent', useragent_header[0][1])
    if cookie_jar:
        kwargs.setdefault('cookies', cookie_jar)

    with ignore_insecure_warning(**kwargs):
        return requests.head(url, **kwargs)
