#  Copyright (C) 2021 Palantir Technologies Inc. All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging
import oauthlib.oauth2.rfc6749.errors
from typing import List, Optional
from urllib.parse import urlunparse


from ._flow import Flow
from ._utils import get_hostname
from ._webserver import run_local_server
from .cache import (
    CredentialsCache,
    NOOP,
    READ_WRITE,
    _load_user_credentials_from_file,
    _save_user_account_credentials,
)
from .errors import CredentialsError

_LOGGER = logging.getLogger(__name__)

AUTH_URI = "/multipass/api/oauth2/authorize"
TOKEN_URI = "/multipass/api/oauth2/token"
CALLBACK_CLIENT_URI = "/multipass/api/oauth2/callback"


def get_user_credentials(
    scopes: List[str],
    hostname: str,
    client_id: str,
    client_secret: Optional[str] = None,
    credentials_cache: CredentialsCache = READ_WRITE,
    use_local_webserver: bool = False,
):
    """
    Gets user account credentials. This function authenticates using user credentials, either loading saved credentials
    from the cache or by going through the OAuth 2.0 flow. The default read-write cache attempts to read credentials
    from a file on disk. If these credentials are not found or are invalid, it begins an OAuth 2.0 flow to get
    credentials. You'll open a browser window asking for you to authenticate to your Foundry account. The permissions it
    requests correspond to the scopes you've provided.

    Parameters
    ----------
    scopes : list[str]
        A list of scopes to use when authenticating to Foundry APIs.
    hostname : str
        The hostname of the Foundry account being authenticated against.
    client_id : str
        The client id to use when prompting for user credentials.
    client_secret : str, optional
        The client secrets to use when prompting for user credentials. If you are a tool or library author of a
        non-public client, you must override the default value with a client secret associated with your application.
    credentials_cache : palantir_oauth_client.cache.CredentialsCache, optional
        An object responsible for loading and saving user credentials. By default, palantir-auth reads and write
        credentials in ``$HOME/.foundry/oauth`` or ``$APPDATA/.foundry/oauth`` on
        Windows.
    use_local_webserver : bool, optional
        Use a local webserver for the user authentication. Binds a webserver to an open port on ``localhost``
        between 8888 and 8987, inclusive, to receive authentication token. If not set, defaults to ``False``, which
        requests a token via the console.

    Returns
    -------
    credentials : palantir_oauth_client.credentials.Credentials
        Credentials for the user, with the requested scopes.

    Raises
    ------
    palantir_oauth_client.exceptions.CredentialsError
        If unable to get valid user credentials.
    """
    _hostname = get_hostname(hostname)
    if scopes is None:
        scopes = []

    client_config = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": urlunparse(
            ["https", _hostname, CALLBACK_CLIENT_URI, None, None, None]
        ),
        "auth_uri": urlunparse(
            ["https", _hostname, AUTH_URI, None, None, None]
        ),
        "token_uri": urlunparse(
            ["https", _hostname, TOKEN_URI, None, None, None]
        ),
    }

    credentials = credentials_cache.load(hostname=_hostname)
    if credentials is None:
        app_flow = Flow.from_client_config(client_config, scopes=scopes)

        try:
            if use_local_webserver:
                credentials = run_local_server(app_flow)
            else:
                credentials = app_flow.run_console()
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error as exc:
            raise CredentialsError(
                "Unable to get valid credentials: {}".format(exc)
            )

    if credentials and not credentials.valid:
        credentials.refresh()

    credentials_cache.save(credentials)
    return credentials


def save_user_credentials(
    scopes: List[str],
    hostname: str,
    path: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    use_local_webserver: bool = False,
):
    """
    Gets user account credentials and saves them to a credentials file at ``path``. This function authenticates using
    user credentials by going through the OAuth 2.0 flow.

    Parameters
    ----------
    scopes : list[str]
        A list of scopes to use when authenticating to Foundry APIs.
    hostname : str
        The hostname of the Foundry account being authenticated against.
    path : str
        Path to save credentials file.
    client_id : str, optional
        The client id to use when prompting for user credentials. Defaults to a client ID associated with
        palantir-oauth. If you are a tool or library author, you must override the default value with a client ID
        associated with your application.
    client_secret : str, optional
        The client secrets to use when prompting for user credentials. If you are a tool or library author of a
        non-public client, you must override the default value with a client secret associated with your application.
    use_local_webserver : bool, optional
        Use a local webserver for the user authentication. Binds a webserver to an open port on ``localhost``
        between 8888 and 8987, inclusive, to receive authentication token. If not set, defaults to ``False``, which
        requests a token via the console.

    Returns
    -------
    credentials : palantir_oauth_client.credentials.Credentials
        Credentials for the user, with the requested scopes.

    Raises
    ------
    palantir_oauth_client.exceptions.CredentialsError
        If unable to get valid user credentials.
    """
    credentials = get_user_credentials(
        scopes,
        hostname,
        client_id=client_id,
        client_secret=client_secret,
        credentials_cache=NOOP,
        use_local_webserver=use_local_webserver,
    )
    _save_user_account_credentials(credentials, path)


def load_user_credentials(path: str):
    """
    Gets user credentials from file at ``path``.

    Parameters
    ----------
    path : str
        Path to credentials file.

    Returns
    -------
    credentials : palantir_oauth_client.credentials.Credentials

    Raises
    ------
    palantir_oauth_client.exceptions.CredentialsError
        If unable to load user credentials.
    """
    credentials = _load_user_credentials_from_file(path)
    if not credentials:
        raise CredentialsError("Could not load credentials.")
    return credentials


class AuthContext():
    def __init__(self, flow: Flow, url: str):
        self._flow = flow
        self.authorization_url = url

    def fetch_token(self, auth_code: str):
        """
        Gets user account credentials from an authorization code, by exchanging it for a token via the the OAuth 2.0
        flow. No credentials caching is performed.

        Parameters
        ----------
        auth_code : str
            Authorization code acquired by browsing to the URL at ``self.authorization_url``.

        Returns
        -------
        credentials : palantir_oauth_client.credentials.Credentials
            Credentials for the user, with the requested scopes.

        Raises
        ------
        palantir_oauth_client.exceptions.CredentialsError
            If unable to get valid user credentials.
        """
        try:
            self._flow.fetch_token(code=auth_code)
            return self._flow.credentials
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error as exc:
            raise CredentialsError(
                "Unable to get valid credentials: {}".format(exc)
            )


def get_authorization_context(
    scopes: List[str],
    hostname: str,
    client_id: str,
    client_secret: Optional[str] = None,
) -> AuthContext:
    """
    Gets an authorization context object with which can be used to perform the OAuth 2.0 flow.

    The auth context object contains the URL at which the user can authenticate and authorize. The permissions
    it requests correspond to the provided scopes. After opening the URL in a browser window and performing the
    authentication and authorization, the user will be given a code that can be passed to
    ``AuthContext.fetch_token`` to obtain the credentials. No credentials caching is performed.

    This method, together with ``AuthContext.fetch_token`` can be used instead of ``get_user_credentials`` when
    the caller needs finer control the user input/output, and when credentials caching is not required.

    Parameters
    ----------
    scopes : list[str]
        A list of scopes to use when authenticating to Foundry APIs.
    hostname : str
        The hostname of the Foundry account being authenticated against.
    client_id : str
        The client id to use when prompting for user credentials.
    client_secret : str, optional
        The client secrets to use when prompting for user credentials. If you are a tool or library author of a
        non-public client, you must override the default value with a client secret associated with your application.

    Returns
    -------
    auth_context : AuthContext
        An auth context object containing the URL at which the user can perform authentication and authorization.
    """
    _hostname = get_hostname(hostname)
    if scopes is None:
        scopes = []

    client_config = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": urlunparse(
            ["https", _hostname, CALLBACK_CLIENT_URI, None, None, None]
        ),
        "auth_uri": urlunparse(
            ["https", _hostname, AUTH_URI, None, None, None]
        ),
        "token_uri": urlunparse(
            ["https", _hostname, TOKEN_URI, None, None, None]
        ),
    }

    app_flow = Flow.from_client_config(client_config, scopes=scopes)

    url = app_flow.get_authorization_url()

    return AuthContext(app_flow, url)
