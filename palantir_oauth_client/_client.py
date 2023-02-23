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

import datetime
import http.client
import json
import requests
import urllib.parse
from typing import Mapping, Optional, Sequence, Tuple

from ._utils import utcnow
from .errors import RefreshError


_URLENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded"
_AUTHORIZATION_GRANT_TYPE = "authorization_code"
_REFRESH_GRANT_TYPE = "refresh_token"
_RETRY_ATTEMPTS = 2


def _handle_error_response(response_body: str):
    try:
        error_data = json.loads(response_body)
        error_details = "{}: {}".format(
            error_data["error"], error_data.get("error_description")
        )
    except (KeyError, ValueError):
        error_details = response_body

    raise RefreshError(error_details, response_body)


def _parse_expiry(response_data: Mapping) -> Optional[datetime.datetime]:
    expires_in = response_data.get("expires_in", None)

    if expires_in is not None:
        return utcnow() + datetime.timedelta(seconds=expires_in)
    else:
        return None


def _token_endpoint_request(
    token_uri: str, body: Mapping[str, str]
) -> Mapping[str, str]:
    body = urllib.parse.urlencode(body).encode("utf-8")
    headers = {"content-type": _URLENCODED_CONTENT_TYPE}

    retry = 0
    while True:
        response = requests.post(token_uri, body, headers=headers)
        response_body = (
            response.content.decode("utf-8")
            if hasattr(response.content, "decode")
            else response.content
        )
        response_data = json.loads(response_body)

        if response.status_code == http.client.OK:
            break
        else:
            error_desc = response_data.get("error_description") or ""
            error_code = response_data.get("error") or ""
            if (
                any(e == "internal_failure" for e in (error_code, error_desc))
                and retry < _RETRY_ATTEMPTS
            ):
                retry += 1
                continue
            _handle_error_response(response_body)

    return response_data


def refresh_grant(
    token_uri: str,
    refresh_token: str,
    client_id: str,
    client_secret: Optional[str] = None,
    scopes: Optional[Sequence[str]] = None,
) -> Tuple[str, Optional[str], Optional[datetime.datetime], Mapping[str, str]]:
    body = {
        "grant_type": _REFRESH_GRANT_TYPE,
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    if client_secret:
        body["client_secret"] = client_secret
    if scopes:
        body["scope"] = " ".join(scopes)

    response_data = _token_endpoint_request(token_uri, body)

    try:
        access_token = response_data["access_token"]
    except KeyError as caught_exc:
        raise RefreshError(
            "No access token in response.", response_data
        ) from caught_exc

    refresh_token = response_data.get("refresh_token", refresh_token)
    expiry = _parse_expiry(response_data)

    return access_token, refresh_token, expiry, response_data
