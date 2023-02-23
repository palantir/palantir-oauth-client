from expects import *

from palantir_oauth_client.auth import load_user_credentials
from palantir_oauth_client.errors import CredentialsError
from palantir_oauth_client._utils import is_state_valid


class TestAuth:
    def test_load_user_credentials_raises_when_file_doesnt_exist(self):
        expect(lambda: load_user_credentials("path/not/found")).to(
            raise_error(
                CredentialsError,
            )
        )

    def test_redirect_url_state_return_invalid_when_not_matching(self):
        expect(is_state_valid(
            "stored-state",
            "http://127.0.0.1:8890/?code=6d9383e8-2b85-4a61-8d63-aa7f1e6afb99&state=anoth3rState"
        )).to(be_false)

    def test_redirect_url_state_return_valid_when_matching(self):
        expect(is_state_valid(
            "stored-state",
            "http://127.0.0.1:8890/?code=6d9383e8-2b85-4a61-8d63-aa7f1e6afb99&state=stored-state"
        )).to(be_true)
