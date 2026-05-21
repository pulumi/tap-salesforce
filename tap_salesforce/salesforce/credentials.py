import logging
import threading
import time
from collections import namedtuple

import jwt
import requests
from simple_salesforce import SalesforceLogin

LOGGER = logging.getLogger(__name__)


JWTCredentials = namedtuple(
    "JWTCredentials",
    ("jwt_client_id", "jwt_username", "jwt_private_key", "jwt_audience"),
)

OAuthCredentials = namedtuple("OAuthCredentials", ("client_id", "client_secret", "refresh_token"))

PasswordCredentials = namedtuple("PasswordCredentials", ("username", "password", "security_token"))


def parse_credentials(config):
    # JWT is the most specific (4 fields), then OAuth refresh token, then SOAP password.
    # If a tap is configured with multiple sets of credentials during a cutover, the
    # strongest one wins.
    for cls in (JWTCredentials, OAuthCredentials, PasswordCredentials):
        creds = cls(*(config.get(key) for key in cls._fields))
        if all(creds):
            return creds

    raise Exception("Cannot create credentials from config.")


class SalesforceAuth:
    def __init__(self, credentials, is_sandbox=False):
        self.is_sandbox = is_sandbox
        self._credentials = credentials
        self._access_token = None
        self._instance_url = None
        self._auth_header = None
        self.login_timer = None

    def login(self):
        """Attempt to login and set the `instance_url` and `access_token` on success."""

    @property
    def rest_headers(self):
        return {"Authorization": f"Bearer {self._access_token}"}

    @property
    def bulk_headers(self):
        return {
            "X-SFDC-Session": self._access_token,
            "Content-Type": "application/json",
        }

    @property
    def instance_url(self):
        return self._instance_url

    @classmethod
    def from_credentials(cls, credentials, **kwargs):
        if isinstance(credentials, JWTCredentials):
            return SalesforceAuthJWT(credentials, **kwargs)

        if isinstance(credentials, OAuthCredentials):
            return SalesforceAuthOAuth(credentials, **kwargs)

        if isinstance(credentials, PasswordCredentials):
            return SalesforceAuthPassword(credentials, **kwargs)

        raise Exception("Invalid credentials")


class SalesforceAuthJWT(SalesforceAuth):
    # Salesforce caps the JWT `exp` claim at 5 minutes; keep it well under that.
    JWT_LIFETIME_SECONDS = 180
    TOKEN_REFRESH_PERIOD = 900

    def _build_assertion(self):
        now = int(time.time())
        claims = {
            "iss": self._credentials.jwt_client_id,
            "sub": self._credentials.jwt_username,
            "aud": self._credentials.jwt_audience,
            "exp": now + self.JWT_LIFETIME_SECONDS,
        }
        return jwt.encode(claims, self._credentials.jwt_private_key, algorithm="RS256")

    def login(self):
        token_url = f"{self._credentials.jwt_audience.rstrip('/')}/services/oauth2/token"
        resp = None
        try:
            LOGGER.info("Attempting login via OAuth2 JWT Bearer")

            resp = requests.post(
                token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._build_assertion(),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            resp.raise_for_status()
            auth = resp.json()

            LOGGER.info("JWT login successful")
            self._access_token = auth["access_token"]
            self._instance_url = auth["instance_url"]
        except Exception as e:
            error_message = str(e)
            if resp is not None:
                error_message = error_message + f", Response from Salesforce: {resp.text}"
            raise Exception(error_message) from e

        # Schedule refresh only on success. A failed login left the timer alive
        # in `finally`, keeping the non-daemon thread running until the next
        # refresh fired against the same broken credentials - Meltano tasks
        # looked hung until Airflow timed them out.
        LOGGER.info("Starting new login timer")
        self.login_timer = threading.Timer(self.TOKEN_REFRESH_PERIOD, self.login)
        self.login_timer.daemon = True
        self.login_timer.start()


class SalesforceAuthOAuth(SalesforceAuth):
    # The minimum expiration setting for SF Refresh Tokens is 15 minutes
    REFRESH_TOKEN_EXPIRATION_PERIOD = 900

    @property
    def _login_body(self):
        return {"grant_type": "refresh_token", **self._credentials._asdict()}

    @property
    def _login_url(self):
        login_url = "https://login.salesforce.com/services/oauth2/token"

        if self.is_sandbox:
            login_url = "https://test.salesforce.com/services/oauth2/token"

        return login_url

    def login(self):
        try:
            LOGGER.info("Attempting login via OAuth2")

            resp = requests.post(
                self._login_url,
                data=self._login_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            resp.raise_for_status()
            auth = resp.json()

            LOGGER.info("OAuth2 login successful")
            self._access_token = auth["access_token"]
            self._instance_url = auth["instance_url"]
        except Exception as e:
            error_message = str(e)
            if resp:
                error_message = error_message + f", Response from Salesforce: {resp.text}"
            raise Exception(error_message) from e
        finally:
            LOGGER.info("Starting new login timer")
            self.login_timer = threading.Timer(self.REFRESH_TOKEN_EXPIRATION_PERIOD, self.login)
            self.login_timer.start()


class SalesforceAuthPassword(SalesforceAuth):
    def login(self):
        login = SalesforceLogin(sandbox=self.is_sandbox, **self._credentials._asdict())

        self._access_token, host = login
        self._instance_url = "https://" + host
