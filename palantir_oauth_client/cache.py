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

import configparser
import errno
import logging
import os
import os.path
from os import name as os_name
from typing import Optional

from palantir_oauth_client._utils import get_hostname

from .credentials import Credentials
from .errors import RefreshError


_LOGGER = logging.getLogger(__name__)


_DIRNAME = ".foundry"
_FILENAME = "oauth"


def _get_default_credentials_path(
    credentials_dirname: str, credentials_filename: str
) -> str:
    config_path = None

    if os_name == "nt":
        config_path = os.getenv("APPDATA")
    if not config_path:
        config_path = os.path.expanduser("~")

    config_path = os.path.join(config_path, credentials_dirname)
    return os.path.join(config_path, credentials_filename)


def _load_user_credentials_from_config(
    config: configparser.ConfigParser, hostname: Optional[str] = None
) -> Optional[Credentials]:
    content = (
        config[hostname] if config.has_section(hostname) else config["DEFAULT"]
    )
    credentials = Credentials(
        token=content.get("access_token"),
        refresh_token=content.get("refresh_token"),
        token_uri=content.get("token_uri"),
        client_id=content.get("client_id"),
        client_secret=content.get("client_secret"),
        scopes=[
            scope.strip() for scope in content.get("scopes", "").split(",")
        ],
    )

    if credentials and not credentials.valid:
        try:
            credentials.refresh()
        except RefreshError:
            # Credentials could be expired or revoked. Try to reauthorize.
            return None

    return credentials


def _load_user_credentials_from_file(
    credentials_path: str,
    hostname: Optional[str] = None,
) -> Optional[Credentials]:
    config = configparser.ConfigParser()
    try:
        config.read(credentials_path)
    except (IOError, ValueError) as exc:
        _LOGGER.debug(
            "Error loading credentials from {}: {}".format(
                credentials_path, str(exc)
            )
        )
        return None

    return _load_user_credentials_from_config(config, hostname=hostname)


def _save_user_account_credentials(
    credentials: Credentials, credentials_path: str
):
    config_dir = os.path.dirname(credentials_path)
    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                _LOGGER.warning("Unable to create credentials directory.")
                return

    config = configparser.ConfigParser()

    if os.path.exists(credentials_path):
        try:
            config.read(credentials_path)
        except (IOError, ValueError) as exc:
            _LOGGER.debug(
                "Error loading credentials from {}: {}".format(
                    credentials_path, str(exc)
                )
            )

    hostname = "DEFAULT"
    if credentials.token_uri is not None:
        _hostname = get_hostname(credentials.token_uri)
        if _hostname is not None:
            hostname = _hostname
    if hostname != "DEFAULT" and not config.has_section(hostname):
        config.add_section(hostname)

    if credentials.token_uri is not None:
        config[hostname]["token_uri"] = credentials.token_uri
    if credentials.client_id is not None:
        config[hostname]["client_id"] = credentials.client_id
    if credentials.client_secret is not None:
        config[hostname]["client_secret"] = credentials.client_secret
    if credentials.scopes is not None:
        config[hostname]["scopes"] = ",".join(credentials.scopes)
    if credentials.refresh_token is not None:
        config[hostname]["refresh_token"] = credentials.refresh_token

    try:
        with open(credentials_path, "w") as credentials_file:
            config.write(credentials_file)
    except IOError:
        _LOGGER.warning("Unable to save credentials.")


class CredentialsCache(object):
    def load(self, hostname: Optional[str] = None) -> Credentials:
        pass

    def save(self, credentials: Credentials):
        pass


class ReadWriteCredentialsCache(CredentialsCache):
    """
    A :class:`~palantir_oauth_client.cache.CredentialsCache`
    which writes to disk and reads cached credentials from disk.
    """

    def __init__(self, dirname=_DIRNAME, filename=_FILENAME):
        super(ReadWriteCredentialsCache, self).__init__()
        self._path = _get_default_credentials_path(dirname, filename)

    def load(self, hostname: Optional[str] = None) -> Optional[Credentials]:
        return _load_user_credentials_from_file(self._path, hostname=hostname)

    def save(self, credentials: Credentials):
        _save_user_account_credentials(credentials, self._path)


class WriteOnlyCredentialsCache(CredentialsCache):
    """
    A :class:`~palantir_oauth_client.cache.CredentialsCache` which writes to disk, but doesn't read from disk.
    Use this class to reauthorize against Foundry APIs and cache your credentials for later.
    """

    def __init__(self, dirname=_DIRNAME, filename=_FILENAME):
        super(WriteOnlyCredentialsCache, self).__init__()
        self._path = _get_default_credentials_path(dirname, filename)

    def save(self, credentials: Credentials):
        _save_user_account_credentials(credentials, self._path)


NOOP = CredentialsCache()
"""
Noop implementation of credentials cache. This cache always reauthorizes and never save credentials to disk.
"""

READ_WRITE = ReadWriteCredentialsCache()
"""
Write credentials to disk and read cached credentials from disk.
"""

REAUTH = WriteOnlyCredentialsCache()
"""
Write credentials to disk. Never read cached credentials from disk. Use this to reauthenticate and refresh the
cached credentials.
"""
