Palantir OAuth Client
==============

A library for performing OAuth2 authentication with Multipass in order to obtain credentials for querying Foundry APIs.

This library supports two modes of operation for the [Authorization code](https://oauth.net/2/grant-types/authorization-code/)
OAuth2 flow:

1. Command line prompt: A user will be prompted to navigate to Foundry and enter the resulting ``authorization_code``
   in their console after successful authentication.
   
2. Local webserver: A local webserver will be created to receive the redirect after successful authentication. The token
   exchange will be performed automatically.

If the ``offline_access`` scope is specified, the credential will additionally contain a refresh token. When loading
cached credentials (see below), the refresh token will be used to update invalid or expired credentials. In the case
credentials cannot be obtained the user will be prompted to log in as above.

Usage
-----
Use the ``palantir_oauth_client.get_user_credentials()`` function to authenticate to Foundry APIs. 

```python
import requests
from palantir_oauth_client import get_user_credentials

hostname = "127.0.0.1:8080"
client_id = "f5496be223e4db85c6a7c99bc5c2d81a"
credentials = get_user_credentials(["offline_access"], hostname, client_id)

headers = {"Authorization": "Bearer " + credentials.token}
response = requests.get(f"https://{hostname}/multipass/api/me", headers=headers)
print("Hello, {}!".format(response.json().get("username")))
```

## Client Registration

A third-party client application needs to have been created in Multipass and the ``client_id`` provided when calling
``palantir_oauth_client.get_user_credentials()``. This client should be registered as a _Public client_ (native or single-page
application) when it is not possible to securely store the ``client_secret``. The library uses the
[PKCE OAuth2 extension](https://oauth.net/2/pkce/) for all requests regardless of the type of client that has been
registered.

The following redirect URIs should use be specified for each mode of operation:

1. Command line prompt: ``https://<hostname>/multipass/api/oauth2/callback``

2. Local webserver: ``http://127.0.0.1/``

## Caching

When obtaining credentials using ``palantir_oauth_client.get_user_credentials()`` you may specify a
``palantir_oauth_client.cache.CredentialsCache``. There are three implementations:

1. ``palantir_oauth_client.cache.READ_WRITE`` (default): A read-write cache that will persist credentials to disk when
   ``offline_access`` scope is requested. The cached refresh tokens will be used when obtaining credentials where
   possible to avoid explicit re-authentication.
   
2. ``palantir_oauth_client.cache.REAUTH``: A write-only cache that will persist credentials to disk when ``offline_access``
   scope is requested but will require reauthentication when obtaining credentials.
   
3. ``palantir_oauth_client.cache.NOOP``: Always requires reauthentication and never persists credentials to disk.

Persisted credentials will be stored in the default user home directory at ``~/.foundry/oauth``. Caching should
only be used when this home directory is secure and inaccessible by other users who would not otherwise have access to
the Foundry credentials.

## Contributing

See the [CONTRIBUTING.md](./CONTRIBUTING.md) document. Releases are published to [pypi](https://pypi.org/project/palantir-oauth-client/) on tag builds and are automatically re-published to conda using conda-forge.

## License
This project is made available under the [Apache 2.0 License](/LICENSE).
