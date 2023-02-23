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

import requests_oauthlib
from datetime import datetime
from typing import Any, List, Mapping, Optional

from ._client import refresh_grant
from ._utils import CLOCK_SKEW, utcnow
from .errors import RefreshError


class Credentials(object):
    """
    Credentials using OAuth 2.0 access and refresh tokens.
    """

    def __init__(
            self,
            token: str,
            refresh_token: Optional[str] = None,
            token_uri: Optional[str] = None,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            scopes: Optional[List[str]] = None,
            default_scopes: Optional[List[str]] = None,
            expiry: Optional[datetime] = None,
    ):
        """
        Args:
            token (Optional(str)): The OAuth 2.0 access token. Can be None if refresh information is provided.
            refresh_token (str): The OAuth 2.0 refresh token. If specified, credentials can be refreshed.
            token_uri (str): The OAuth 2.0 authorization server's token endpoint URI. Must be specified for refresh,
                can be left as None if the token can not be refreshed.
            client_id (str): The OAuth 2.0 client ID. Must be specified for refresh, can be left as None if the token
                can not be refreshed.
            client_secret(str): The OAuth 2.0 client secret. Can be left as None for public clients.
            scopes (Sequence[str]): The scopes used to obtain authorization. This parameter is used by
                :meth:`has_scopes`. OAuth 2.0 credentials can not request additional scopes after authorization. The
                scopes must be derivable from the refresh token if refresh information is provided.
            default_scopes (Sequence[str]): Default scopes passed by a Foundry client library. Use 'scopes' for
                user-defined scopes.
            expiry(datetime): The OAuth 2.0 token expiry.
        """
        super(Credentials, self).__init__()
        self.token = token
        self.expiry = expiry
        self._refresh_token = refresh_token
        self._scopes = scopes
        self._default_scopes = default_scopes
        self._token_uri = token_uri
        self._client_id = client_id
        self._client_secret = client_secret

    @classmethod
    def from_session(
            cls,
            session: requests_oauthlib.OAuth2Session,
            client_config: Mapping[str, Any] = None,
    ):
        """
        Creates :class:`palantir_oauth_client.credentials.Credentials` from a :class:`requests_oauthlib.OAuth2Session`.

        :meth:`fetch_token` must be called on the session before calling this. This uses the session's auth token
        and the provided client configuration to create :class:`palantir_oauth_client.credentials.Credentials`.
        This allows you to use the credentials from the session with Foundry API client libraries.
        """
        client_config = client_config if client_config is not None else {}

        if not session.token:
            raise ValueError(
                "There is no access token for this session, did you call "
                "fetch_token?"
            )

        credentials = cls(
            session.token["access_token"],
            refresh_token=session.token.get("refresh_token"),
            token_uri=client_config.get("token_uri"),
            client_id=client_config.get("client_id"),
            client_secret=client_config.get("client_secret"),
            scopes=session.scope,
        )
        credentials.expiry = datetime.utcfromtimestamp(
            session.token["expires_at"]
        )
        return credentials

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, d):
        self.token = d.get("token")
        self.expiry = d.get("expiry")
        self._refresh_token = d.get("_refresh_token")
        self._scopes = d.get("_scopes")
        self._default_scopes = d.get("_default_scopes")
        self._token_uri = d.get("_token_uri")
        self._client_id = d.get("_client_id")
        self._client_secret = d.get("_client_secret")

    @property
    def refresh_token(self) -> Optional[str]:
        return self._refresh_token

    @property
    def scopes(self) -> Optional[List[str]]:
        return self._scopes

    @property
    def token_uri(self) -> Optional[str]:
        return self._token_uri

    @property
    def client_id(self) -> Optional[str]:
        return self._client_id

    @property
    def client_secret(self) -> Optional[str]:
        return self._client_secret

    @property
    def expired(self) -> bool:
        if not self.expiry:
            return False

        # Remove 10 seconds from expiry to err on the side of reporting expiration early.
        skewed_expiry = self.expiry - CLOCK_SKEW
        return utcnow() >= skewed_expiry

    @property
    def valid(self):
        """Checks the validity of the credentials.

        This is True if the credentials have a :attr:`token` and the token is not :attr:`expired`.
        """
        return self.token is not None and not self.expired

    def refresh(self):
        if (
                self._refresh_token is None
                or self._token_uri is None
                or self._client_id is None
        ):
            raise RefreshError(
                "The credentials do not contain the necessary fields need to "
                "refresh the access token. You must specify refresh_token, "
                "token_uri, client_id."
            )

        scopes = (
            self._scopes if self._scopes is not None else self._default_scopes
        )

        access_token, refresh_token, expiry, grant_response = refresh_grant(
            self._token_uri,
            self._refresh_token,
            self._client_id,
            self._client_secret,
            scopes,
        )

        self.token = access_token
        self.expiry = expiry
        self._refresh_token = refresh_token

        if scopes and "scopes" in grant_response:
            requested_scopes = frozenset(scopes)
            granted_scopes = frozenset(grant_response["scopes"].split())
            scopes_requested_but_not_granted = (
                    requested_scopes - granted_scopes
            )
            if scopes_requested_but_not_granted:
                raise RefreshError(
                    "Not all requested scopes were granted by the authorization server, missing scopes {}.".format(
                        ", ".join(scopes_requested_but_not_granted)
                    )
                )
