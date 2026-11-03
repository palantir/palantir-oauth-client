import os
import pytest
from expects import *
from mockito import mock, when

from palantir_oauth_client._flow import Flow


RELAX_TOKEN_SCOPE = "OAUTHLIB_RELAX_TOKEN_SCOPE"


class TestFlow:
    CLIENT_CONFIG = {
        "token_uri": "https://token-uri",
        "client_secret": "client-secret",
    }
    TOKEN = {"access_token": "access-token"}

    @pytest.fixture(autouse=True)
    def before(self):
        previous_value = os.environ.pop(RELAX_TOKEN_SCOPE, None)
        self.session = mock()
        self.relax_token_scope_while_fetching = None
        yield
        os.environ.pop(RELAX_TOKEN_SCOPE, None)
        if previous_value is not None:
            os.environ[RELAX_TOKEN_SCOPE] = previous_value

    def test_fetch_token_relaxes_token_scope_while_fetching(self):
        when(self.session).fetch_token(...).thenAnswer(self._fetch_token)

        token = Flow(self.session, self.CLIENT_CONFIG).fetch_token(code="code")

        expect(token).to(equal(self.TOKEN))
        expect(self.relax_token_scope_while_fetching).to(equal("true"))

    def test_fetch_token_unsets_relaxed_token_scope_afterwards(self):
        when(self.session).fetch_token(...).thenAnswer(self._fetch_token)

        Flow(self.session, self.CLIENT_CONFIG).fetch_token(code="code")

        expect(os.environ.get(RELAX_TOKEN_SCOPE)).to(be_none)

    def test_fetch_token_unsets_relaxed_token_scope_after_error(self):
        when(self.session).fetch_token(...).thenRaise(ValueError("failed"))

        expect(
            lambda: Flow(self.session, self.CLIENT_CONFIG).fetch_token(code="code")
        ).to(raise_error(ValueError, "failed"))

        expect(os.environ.get(RELAX_TOKEN_SCOPE)).to(be_none)

    def test_fetch_token_restores_previous_token_scope_setting(self):
        os.environ[RELAX_TOKEN_SCOPE] = "previous"
        when(self.session).fetch_token(...).thenAnswer(self._fetch_token)

        Flow(self.session, self.CLIENT_CONFIG).fetch_token(code="code")

        expect(os.environ.get(RELAX_TOKEN_SCOPE)).to(equal("previous"))

    def _fetch_token(self, *args, **kwargs):
        self.relax_token_scope_while_fetching = os.environ.get(RELAX_TOKEN_SCOPE)
        return self.TOKEN
