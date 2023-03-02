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
import calendar
import requests_oauthlib
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence, Tuple
from urllib3.util import parse_url
from urllib.parse import urlparse, parse_qs

CLOCK_SKEW_SECONDS = 10
CLOCK_SKEW = timedelta(seconds=CLOCK_SKEW_SECONDS)

_REQUIRED_CONFIG_KEYS = frozenset(("auth_uri", "token_uri", "client_id"))


def get_hostname(url: str) -> str:
    _url = parse_url(url)
    hostname = _url.hostname
    if _url.port is not None:
        hostname = hostname + ":" + str(_url.port)
    return hostname


def utcnow() -> datetime:
    """Returns the current UTC datetime."""
    return datetime.utcnow()


def datetime_to_secs(value: datetime) -> int:
    """Convert a datetime object to the number of seconds since the UNIX epoch."""
    return calendar.timegm(value.utctimetuple())


def session_from_client_config(
    client_config: Mapping[str, Any], scopes: Sequence[str], **kwargs
) -> Tuple[requests_oauthlib.OAuth2Session, Mapping[str, Any]]:
    if not _REQUIRED_CONFIG_KEYS.issubset(client_config.keys()):
        raise ValueError("Client config is not in the correct format.")

    session = requests_oauthlib.OAuth2Session(
        client_id=client_config["client_id"], scope=scopes, **kwargs
    )

    return session, client_config


def is_state_valid(
    stored_state,
    url
) -> (bool, str):
    parsed_url = urlparse(url)
    url_query = parse_qs(parsed_url.query)
    received_state = url_query.get("state", None)

    return received_state and stored_state == received_state[0]
