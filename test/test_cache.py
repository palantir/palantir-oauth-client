import os
import os.path
import shutil
import tempfile
from expects import *
from mockito import patch

from palantir_oauth_client import cache
from palantir_oauth_client.credentials import Credentials


class TestCache:
    def test_import_unwriteable_fs(self):
        def raise_unwriteable():
            raise PermissionError()

        with patch(os.path, "exists", lambda _: False), patch(
            os, "makedirs", raise_unwriteable
        ):
            expect(cache.NOOP).to(not_(be_none))

    def test_get_default_credentials_path_windows_without_appdata(self):
        with patch(cache, "os_name", "nt"):
            expect(
                cache._get_default_credentials_path("dirname", "filename")
            ).to(not_(be_none))

    def test_save_user_account_credentials_without_directory(self):
        credentials = Credentials(
            token="access-token",
            refresh_token="refresh-token",
            token_uri="https://token-uri",
            client_id="client-id",
            client_secret="client-secret",
            scopes=["offline_access", "gatekeeper:view-resource"],
        )
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, ".foundry/oauth")
            expect(os.path.exists(".foundry/")).to(be_false)

            cache._save_user_account_credentials(credentials, path)

            with open(path, "r") as f:
                content = "\n".join([line.strip() for line in f.readlines()])

            expect(content).to(
                equal(
                    """[token-uri]
token_uri = https://token-uri
client_id = client-id
client_secret = client-secret
scopes = offline_access,gatekeeper:view-resource
refresh_token = refresh-token
"""
                )
            )
        finally:
            shutil.rmtree(tmp)

    def test_read_write_sets_path(self):
        credential_cache = cache.ReadWriteCredentialsCache(
            dirname="dirtest", filename="filetest"
        )
        path = os.path.normpath(credential_cache._path)
        parts = path.split(os.sep)
        expect(parts[-1]).to(equal("filetest"))
        expect(parts[-2]).to(equal("dirtest"))

    def test_write_only_sets_path(self):
        credential_cache = cache.WriteOnlyCredentialsCache(
            dirname="dirtest", filename="filetest"
        )
        path = os.path.normpath(credential_cache._path)
        parts = path.split(os.sep)
        expect(parts[-1]).to(equal("filetest"))
        expect(parts[-2]).to(equal("dirtest"))

    def test_read_uses_default_section(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, ".foundry/credentials")
            os.mkdir(os.path.join(tmp, ".foundry"))
            with open(path, "w") as f:
                f.write(
                    """[DEFAULT]
token_uri = https://token_uri
client_id = client-id
client_secret = client-secret
scopes = offline_access,gatekeeper:view-resource
refresh_token = refresh-token
"""
                )

            with patch(Credentials, "refresh", lambda: None):
                credentials = cache._load_user_credentials_from_file(
                    path, "random"
                )

            expect(credentials.refresh_token).to(equal("refresh-token"))
            expect(credentials.token_uri).to(equal("https://token_uri"))
            expect(credentials.client_id).to(equal("client-id"))
            expect(credentials.client_secret).to(equal("client-secret"))
            expect(credentials.scopes).to(
                contain_exactly("offline_access", "gatekeeper:view-resource")
            )
        finally:
            shutil.rmtree(tmp)
