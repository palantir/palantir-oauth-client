import json
import pytest
import requests
from datetime import datetime, timedelta
from expects import *
from mockito import ANY, mock, patch

from palantir_oauth_client._client import refresh_grant
from palantir_oauth_client.errors import RefreshError


now = datetime.utcnow()


class TestClient:
    TOKEN_URI = "https://token-uri"
    CLIENT_ID = "client-id"
    CLIENT_SECRET = "client-secret"
    ACCESS_TOKEN = "access-token"
    REFRESH_TOKEN = "refresh-token"
    EXPIRY = now + timedelta(seconds=10)
    SCOPES = ["scope"]
    HEADERS = {"content-type": "application/x-www-form-urlencoded"}
    BODY = b"grant_type=refresh_token&client_id=client-id&refresh_token=refresh-token&client_secret=client-secret&scope=scope"

    response: requests.Response

    @pytest.fixture(autouse=True)
    def before(self):
        self.response = mock(requests.Response)

    def test_refresh_grant(self):
        self.response.content = json.dumps(
            {  # noqa
                "access_token": self.ACCESS_TOKEN,
                "expires_in": 10,
                "refresh_token": self.REFRESH_TOKEN,
            }
        )
        self.response.status_code = 200  # noqa

        access_token, refresh_token, expiry, response_data = self._test()

        expect(access_token).to(equal(self.ACCESS_TOKEN))
        expect(refresh_token).to(equal(self.REFRESH_TOKEN))
        expect(expiry).to(be_above(self.EXPIRY))

    def test_refresh_grant_without_expiry(self):
        self.response.content = json.dumps(
            {  # noqa
                "access_token": self.ACCESS_TOKEN,
                "refresh_token": self.REFRESH_TOKEN,
            }
        )
        self.response.status_code = 200  # noqa

        access_token, refresh_token, expiry, response_data = self._test()

        expect(access_token).to(equal(self.ACCESS_TOKEN))
        expect(refresh_token).to(equal(self.REFRESH_TOKEN))
        expect(expiry).to(be_none)

    def test_refresh_grant_without_access_token(self):
        self.response.content = json.dumps(
            {"refresh_token": self.REFRESH_TOKEN}  # noqa
        )
        self.response.status_code = 200  # noqa

        expect(lambda: self._test()).to(
            raise_error(
                RefreshError,
                "No access token in response.",
                ANY,
            )
        )

    def test_retryable_error(self):
        self.response.content = json.dumps(
            {"error": "internal_failure"}  # noqa
        )
        self.response.status_code = 500  # noqa

        def _post(token_uri, body, headers):
            if (
                token_uri == self.TOKEN_URI
                and headers == self.HEADERS
                and body == self.BODY
            ):
                result = self.response
                self.response = mock(requests.Response)
                self.response.content = json.dumps(
                    {  # noqa
                        "access_token": self.ACCESS_TOKEN,
                        "refresh_token": self.REFRESH_TOKEN,
                    }
                )
                self.response.status_code = 200  # noqa
                return result

        with patch(requests, "post", _post):
            access_token, refresh_token, expiry, response_data = refresh_grant(
                token_uri=self.TOKEN_URI,
                refresh_token=self.REFRESH_TOKEN,
                client_id=self.CLIENT_ID,
                client_secret=self.CLIENT_SECRET,
                scopes=self.SCOPES,
            )

        expect(access_token).to(equal(self.ACCESS_TOKEN))
        expect(refresh_token).to(equal(self.REFRESH_TOKEN))
        expect(expiry).to(be_none)

    def test_parseable_error(self):
        self.response.content = json.dumps(
            {  # noqa
                "error": "Some error",
                "error_description": "Some error description",
            }
        )
        self.response.status_code = 500  # noqa

        expect(lambda: self._test()).to(
            raise_error(
                RefreshError,
                "Some error: Some error description",
                ANY,
            )
        )

    def test_unparseable_error(self):
        self.response.content = json.dumps(
            {  # noqa
                "random": "Some message",
            }
        )
        self.response.status_code = 500  # noqa

        expect(lambda: self._test()).to(
            raise_error(
                RefreshError,
                '{"random": "Some message"}',
                ANY,
            )
        )

    def _test(self):
        def _post(token_uri, body, headers):
            if (
                token_uri == self.TOKEN_URI
                and headers == self.HEADERS
                and body == self.BODY
            ):
                return self.response

        with patch(requests, "post", _post):
            return refresh_grant(
                token_uri=self.TOKEN_URI,
                refresh_token=self.REFRESH_TOKEN,
                client_id=self.CLIENT_ID,
                client_secret=self.CLIENT_SECRET,
                scopes=self.SCOPES,
            )
