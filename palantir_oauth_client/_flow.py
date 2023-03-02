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

import hashlib
import logging
import os
import requests_oauthlib
import webbrowser
import wsgiref.simple_server
import wsgiref.util
from base64 import urlsafe_b64encode
from string import ascii_letters, digits
from typing import Any, Callable, Iterable, Mapping, Sequence, Tuple
from .errors import CsrfError

try:
    from secrets import SystemRandom
except ImportError:
    from random import SystemRandom

from ._utils import session_from_client_config, is_state_valid
from .credentials import Credentials


_LOGGER = logging.getLogger(__name__)


class Flow(object):

    _DEFAULT_AUTH_PROMPT_MESSAGE = (
        "Please visit this URL to authorize this application: {url}"
    )
    _DEFAULT_AUTH_CODE_MESSAGE = "Enter the authorization code: "
    _DEFAULT_WEB_SUCCESS_MESSAGE = (
        "The authentication flow has completed. You may close this window."
    )

    def __init__(
        self,
        oauth2session: requests_oauthlib.OAuth2Session,
        client_config: Mapping[str, Any],
        redirect_uri: str = None,
        code_verifier: str = None,
    ) -> None:
        self.client_config = client_config
        self.oauth2session = oauth2session
        self.redirect_uri = redirect_uri
        self.code_verifier = code_verifier

    @classmethod
    def from_client_config(
        cls, client_config: Mapping[str, Any], scopes: Sequence[str], **kwargs
    ) -> "Flow":
        # these args cannot be passed to requests_oauthlib.OAuth2Session
        code_verifier = kwargs.pop("code_verifier", None)
        session, client_config = session_from_client_config(
            client_config, scopes, **kwargs
        )
        redirect_uri = kwargs.get("redirect_uri", None)
        return cls(session, client_config, redirect_uri, code_verifier)

    @property
    def redirect_uri(self) -> str:
        return self.oauth2session.redirect_uri

    @redirect_uri.setter
    def redirect_uri(self, value) -> None:
        self.oauth2session.redirect_uri = value

    @property
    def credentials(self) -> Credentials:
        return Credentials.from_session(self.oauth2session, self.client_config)

    def authorization_url(self, **kwargs) -> Tuple[str, str]:
        kwargs.setdefault("access_type", "offline")
        if self.code_verifier is None:
            chars = ascii_letters + digits + "-._~"
            rnd = SystemRandom()
            random_verifier = [rnd.choice(chars) for _ in range(0, 128)]
            self.code_verifier = "".join(random_verifier)

        code_hash = hashlib.sha256()
        code_hash.update(str.encode(self.code_verifier))
        unencoded_challenge = code_hash.digest()
        b64_challenge = urlsafe_b64encode(unencoded_challenge)
        code_challenge = b64_challenge.decode().split("=")[0]
        kwargs.setdefault("code_challenge", code_challenge)
        kwargs.setdefault("code_challenge_method", "S256")
        url, state = self.oauth2session.authorization_url(
            self.client_config["auth_uri"], **kwargs
        )

        return url, state

    def fetch_token(self, **kwargs) -> Mapping[str, str]:
        kwargs.setdefault("client_secret", self.client_config["client_secret"])
        kwargs.setdefault("code_verifier", self.code_verifier)

        # N.B. Multipass doesn't currently return the complete set of scopes so we have to allow mismatched scopes
        previous_value = os.environ.get("OAUTHLIB_RELAX_TOKEN_SCOPE", None)
        try:
            os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "true"
            return self.oauth2session.fetch_token(
                self.client_config["token_uri"], **kwargs
            )
        finally:
            if previous_value is not None:
                os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = previous_value

    def get_authorization_url(
        self,
        **kwargs
    ) -> str:
        kwargs.setdefault("prompt", "consent")

        self.redirect_uri = "callback".join(
            self.client_config["auth_uri"].rsplit("authorize", 1)
        )

        auth_url, _ = self.authorization_url(**kwargs)

        return auth_url

    def run_console(
        self,
        authorization_prompt_message: str = _DEFAULT_AUTH_PROMPT_MESSAGE,
        authorization_code_message: str = _DEFAULT_AUTH_CODE_MESSAGE,
        **kwargs
    ) -> Credentials:
        """Run the flow using the console strategy.

        The console strategy instructs the user to open the authorization URL
        in their browser. Once the authorization is complete the authorization
        server will give the user a code. The user then must copy & paste this
        code into the application. The code is then exchanged for a token.
        """
        auth_url = self.get_authorization_url(**kwargs)

        print(authorization_prompt_message.format(url=auth_url))

        code = input(authorization_code_message)

        self.fetch_token(code=code)
        return self.credentials

    def run_local_server(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        authorization_prompt_message: str = _DEFAULT_AUTH_PROMPT_MESSAGE,
        success_message: str = _DEFAULT_WEB_SUCCESS_MESSAGE,
        open_browser: bool = True,
        **kwargs
    ) -> Credentials:
        """Run the flow using the server strategy.

        The server strategy instructs the user to open the authorization URL in
        their browser and will attempt to automatically open the URL for them.
        It will start a local web server to listen for the authorization
        response. Once authorization is complete the authorization server will
        redirect the user's browser to the local web server. The web server
        will get the authorization code from the response and shutdown. The
        code is then exchanged for a token.
        """
        wsgi_app = _RedirectWSGIApp(success_message)
        wsgiref.simple_server.WSGIServer.allow_reuse_address = False
        local_server = wsgiref.simple_server.make_server(
            host, port, wsgi_app, handler_class=_WSGIRequestHandler
        )

        self.redirect_uri = "http://{}:{}/".format(
            host, local_server.server_port
        )
        auth_url, state = self.authorization_url(**kwargs)

        if open_browser:
            webbrowser.open(auth_url, new=1, autoraise=True)

        print(authorization_prompt_message.format(url=auth_url))

        local_server.handle_request()

        redirect_uri = wsgi_app.last_request_uri
        valid_state = is_state_valid(state, redirect_uri)

        if not valid_state:
            raise CsrfError("CSRF warning: state check failed.")

        # N.B. using https here because oauthlib requires OAuth 2.0 to occur over https
        authorization_response = redirect_uri.replace(
            "http", "https"
        )

        self.fetch_token(authorization_response=authorization_response)

        local_server.server_close()

        return self.credentials


class _WSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, format, *args):
        _LOGGER.debug(format, *args)


class _RedirectWSGIApp(object):
    def __init__(self, success_message: str):
        self.last_request_uri = None
        self._success_message = success_message

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list], None],
    ) -> Iterable[bytes]:
        start_response("200 OK", [("Content-type", "text/plain")])
        self.last_request_uri = wsgiref.util.request_uri(environ)
        return [self._success_message.encode("utf-8")]
