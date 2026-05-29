"""
Module implements the WeConnect Session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Any

import json
import logging
import secrets
import hmac
import hashlib
import time
from pathlib import Path

from urllib.parse import parse_qs, urlparse

import requests
from requests.models import CaseInsensitiveDict

from oauthlib.common import generate_nonce, to_unicode
from oauthlib.oauth2.rfc6749.parameters import prepare_grant_uri
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from carconnectivity.errors import AuthenticationError, RetrievalError, TemporaryAuthenticationError

from carconnectivity_connectors.volkswagen.auth.openid_session import AccessType
from carconnectivity_connectors.volkswagen.auth.vw_web_session import VWWebSession

if TYPE_CHECKING:
    from typing import Tuple, Dict


LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


_CARIAD_TOKEN_URL = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"

_QM_CLIENT_ID = "01da27b0"
_QM_SECRET = "1ab69925ac179aaa4e83abe671a9476d176418b85bd706f1436ca15be647989c"


_ALTERNATE_CLIENT_IDS: dict[str, tuple[str, ...]] = {
    "audi": (
        "16dd7960-431d-4b88-b3a5-35724b2fce01@apps_vw-dilab_com",
    ),
    "volkswagen": (
        "4edc53db-4b79-4e37-b614-19a95dea20dc@apps_vw-dilab_com",
        "a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com",
    ),
}


def _resolve_cache_root() -> Path | None:
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / ".app-atlas-apk-cache"
        if candidate.is_dir():
            return candidate
    return None


_APK_CACHE_ROOT: Path | None = _resolve_cache_root()


def _load_apk_auth_secrets(brand_name: str) -> dict[str, Any]:
    if _APK_CACHE_ROOT is None:
        return {}
    json_path = _APK_CACHE_ROOT / f"{brand_name}.json"
    if not json_path.is_file():
        return {}
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    versions = data.get("versions") or {}
    if not versions:
        return {}
    latest_v = max(versions.keys())
    findings = (versions[latest_v].get("findings") or {})
    return findings.get("auth_secrets") or {}


class AuthConfigResolver:
    def __init__(
        self,
        brand_name: str,
        *,
        hardcoded_client_id: str,
        hardcoded_qmauth_secret: str,
        hardcoded_qmauth_client_id: str,
        hardcoded_token_url: str,
    ) -> None:
        self._brand = brand_name
        self._apk = _load_apk_auth_secrets(brand_name)
        self._hardcoded_client_id = hardcoded_client_id
        self._hardcoded_qmauth_secret = hardcoded_qmauth_secret
        self._hardcoded_qmauth_client_id = hardcoded_qmauth_client_id
        self._hardcoded_token_url = hardcoded_token_url
        if self._apk:
            LOG.debug(
                "AuthConfigResolver(%s): loaded auth_secrets from APK cache: keys=%s",
                brand_name, list(self._apk.keys()),
            )

    def qmauth_secret(self) -> str:
        candidates = self._apk.get("qmauth_secret_candidates") or []
        for c in candidates:
            if isinstance(c, str) and len(c) == 64:
                return c.lower()
        return self._hardcoded_qmauth_secret

    def qmauth_client_id(self) -> str:
        candidates = self._apk.get("client_id_candidates") or []
        for c in candidates:
            if isinstance(c, str) and len(c) == 8 and all(
                ch in "0123456789abcdef" for ch in c.lower()
            ):
                return c.lower()
        return self._hardcoded_qmauth_client_id

    def token_url(self) -> str:
        paths = self._apk.get("token_path_markers_seen") or []
        for p in paths:
            if p == "/auth/v1/idk/oidc/token":
                return "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"
        return self._hardcoded_token_url

    def oauth_client_id_chain(self) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()

        def _add(cid: str) -> None:
            if cid and cid not in seen:
                ordered.append(cid)
                seen.add(cid)

        for c in (self._apk.get("client_id_candidates") or []):
            if isinstance(c, str) and "@apps_vw-dilab_com" in c:
                _add(c)

        for alt in _ALTERNATE_CLIENT_IDS.get(self._brand, ()):
            _add(alt)

        _add(self._hardcoded_client_id)
        return ordered

    def provenance(self) -> dict[str, str]:
        return {
            "qmauth_secret": (
                "apk" if self._apk.get("qmauth_secret_candidates")
                else "hardcoded"
            ),
            "qmauth_client_id": (
                "apk" if self._apk.get("client_id_candidates")
                else "hardcoded"
            ),
            "token_url": (
                "apk" if any(
                    p == "/auth/v1/idk/oidc/token"
                    for p in (self._apk.get("token_path_markers_seen") or [])
                )
                else "hardcoded"
            ),
            "oauth_client_id_chain_size": str(len(self.oauth_client_id_chain())),
        }


def _calculate_x_qmauth(
    secret_hex: str | None = None,
    client_id: str | None = None,
    now: float | None = None,
) -> str:
    secret_hex = secret_hex or _QM_SECRET
    client_id = client_id or _QM_CLIENT_ID
    ts = int((now if now is not None else time.time()) / 100)
    secret_bytes = bytes.fromhex(secret_hex)
    sig = hmac.new(secret_bytes, str(ts).encode("ascii"), hashlib.sha256).hexdigest()
    return f"v1:{client_id}:{sig}"


def _cariad_token_headers(
    user_agent: str,
    *,
    qmauth_secret: str | None = None,
    qmauth_client_id: str | None = None,
) -> dict[str, str]:
    return {
        "Content-Type":           "application/x-www-form-urlencoded",
        "Accept":                 "application/json",
        "Accept-Charset":         "utf-8",
        "User-Agent":             user_agent,
        "x-qmauth":               _calculate_x_qmauth(qmauth_secret, qmauth_client_id),
        "x-platform":             "android",
        "x-android-package-name": "com.volkswagen.weconnect",
        "x-assertion":            "0",
    }


class WeConnectSession(VWWebSession):
    """
    WeConnectSession class handles the authentication and session management for Volkswagen's WeConnect service.
    """
    def __init__(self, session_user, **kwargs) -> None:
        super(WeConnectSession, self).__init__(client_id='a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                                               refresh_url='https://identity.vwgroup.io/oidc/v1/token',
                                               scope='openid profile badge cars dealers vin',
                                               redirect_uri='weconnect://authenticated',
                                               state=None,
                                               session_user=session_user,
                                               **kwargs)

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'Volkswagen/3.61.0-android/14',
            'accept-language': 'de-de',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'x-android-package-name': 'com.volkswagen.weconnect'
        })

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs
    ):
        """Intercept all requests and add weconnect-trace-id header."""

        import secrets
        traceId = secrets.token_hex(16)
        we_connect_trace_id = (traceId[:8] + '-' + traceId[8:12] + '-' + traceId[12:16] + '-' + traceId[16:20] + '-' + traceId[20:]).upper()
        headers = headers or {}
        headers['weconnect-trace-id'] = we_connect_trace_id

        return super(WeConnectSession, self).request(
            method, url, headers=headers, data=data, withhold_token=withhold_token, access_type=access_type, token=token, timeout=timeout, **kwargs
        )

    def login(self):
        super(WeConnectSession, self).login()
        # Clear connection pools before login to prevent stale connection reuse
        # This is critical to prevent "Remote end closed connection without response" errors
        if hasattr(self, '_clear_connection_pools'):
            self._clear_connection_pools()
        # retrieve authorization URL
        authorization_url_str: str = self.authorization_url(url='https://identity.vwgroup.io/oidc/v1/authorize')
        # perform web authentication
        response = self.do_web_auth(authorization_url_str)
        # fetch tokens from web authentication response
        self.fetch_tokens('https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
                          authorization_response=response)

    def refresh(self) -> None:
        # refresh tokens from refresh endpoint
        self.refresh_tokens(
            'https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
        )

    def clear_tokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.
        
        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self.token = None
        LOG.debug("All tokens cleared successfully")

    def authorization_url(self, url, state=None, **kwargs) -> str:
        if state is not None:
            raise AuthenticationError('Do not provide state')
        if self.redirect_uri is None:
            raise AuthenticationError('Redirect URI is not set')

        auth_url: str = prepare_grant_uri(uri=url, client_id=self.client_id, redirect_uri=self.redirect_uri,
                                          response_type='code', scope=self.scope,
                                          state=self.state, nonce=generate_nonce())
        return auth_url

    def fetch_tokens(  # noqa: C901
        self,
        token_url,
        authorization_response=None,
        **_
    ):
        if authorization_response:
            parsed = urlparse(authorization_response)
            params = parse_qs(parsed.query)
            auth_code = params.get('code', [None])[0]
            if not auth_code:
                LOG.error("Authorization response missing authorization code")
                return None
        else:
            LOG.error("No authorization response provided")
            return None

        resolver = AuthConfigResolver(
            "volkswagen",
            hardcoded_client_id=self.client_id,
            hardcoded_qmauth_secret=_QM_SECRET,
            hardcoded_qmauth_client_id=_QM_CLIENT_ID,
            hardcoded_token_url=_CARIAD_TOKEN_URL,
        )
        client_id_chain = resolver.oauth_client_id_chain()

        last_error: AuthenticationError | None = None
        for idx, client_id in enumerate(client_id_chain):
            body = {
                'grant_type': 'authorization_code',
                'code': auth_code,
                'redirect_uri': self.redirect_uri,
                'client_id': client_id,
            }

            request_headers: CaseInsensitiveDict = CaseInsensitiveDict(
                _cariad_token_headers(
                    'Volkswagen/3.61.0-android/14',
                    qmauth_secret=resolver.qmauth_secret(),
                    qmauth_client_id=resolver.qmauth_client_id(),
                )
            )

            token_response = self.post(token_url, headers=request_headers, data=body, allow_redirects=False,
                                       access_type=AccessType.NONE, withhold_token=True)
            if token_response.status_code == requests.codes['ok']:
                if idx > 0:
                    LOG.info(
                        "Token exchange (volkswagen): fallback client_id #%d "
                        "succeeded — primary candidates 4xx'd",
                        idx,
                    )
                token = self.parse_from_body(token_response.text)

                if token is not None:
                    LOG.debug(f"Successfully fetched tokens. Access token expires in: {token.get('expires_in', 'unknown')} seconds")
                    LOG.debug(f"Refresh token available: {'refresh_token' in token}")
                    if not all(key in token for key in ('access_token', 'id_token', 'refresh_token')):
                        LOG.warning("Some expected tokens are missing from the response")
                else:
                    LOG.error("Token parsing returned None")

                return token

            # 4xx on non-last candidate: retry with next client_id
            if 400 <= token_response.status_code < 500 and idx < len(client_id_chain) - 1:
                LOG.debug(
                    "Token exchange (volkswagen) client_id %s..%s rejected "
                    "(HTTP %d) — trying next candidate",
                    client_id[:8], client_id[-4:],
                    token_response.status_code,
                )
                last_error = AuthenticationError(
                    f"Token exchange failed HTTP {token_response.status_code}: "
                    f"{token_response.text[:200]}"
                )
                continue

            # 4xx on last candidate: specific auth error
            if 400 <= token_response.status_code < 500:
                raise AuthenticationError(
                    f"Token exchange failed HTTP {token_response.status_code}: "
                    f"{token_response.text[:200]}"
                )

            # 5xx or other: temporary failure
            raise TemporaryAuthenticationError(
                f'Token could not be fetched due to temporary WeConnect failure: {token_response.status_code}'
            )

        raise last_error or AuthenticationError(
            "Token exchange: all client_id candidates exhausted"
        )

    def parse_from_body(self, token_response, state=None):
        """
            Fix strange token naming before parsing it with OAuthlib.
        """
        try:
            # Tokens are in body of response in json format
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError as err:
            raise TemporaryAuthenticationError('Token could not be refreshed due to temporary WeConnect failure: json could not be decoded') from err
        # Fix token keys, we want access_token instead of accessToken
        if 'accessToken' in token:
            token['access_token'] = token.pop('accessToken')
        # Fix token keys, we want id_token instead of idToken
        if 'idToken' in token:
            token['id_token'] = token.pop('idToken')
        # Fix token keys, we want refresh_token instead of refreshToken
        if 'refreshToken' in token:
            token['refresh_token'] = token.pop('refreshToken')
        # generate json from fixed dict
        fixed_token_response = to_unicode(json.dumps(token)).encode("utf-8")
        # Let OAuthlib parse the token (this internally sets self.token)
        parsed_token = super(WeConnectSession, self).parse_from_body(token_response=fixed_token_response, state=state)
        return parsed_token

    def refresh_tokens(
        self,
        token_url,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **_
    ):
        """
        Refreshes the authentication tokens using the provided refresh token.
        Args:
            token_url (str): The URL to request new tokens from.
            refresh_token (str, optional): The refresh token to use. Defaults to None.
            auth (tuple, optional): Authentication credentials. Defaults to None.
            timeout (float or tuple, optional): How long to wait for the server to send data before giving up. Defaults to None.
            headers (dict, optional): Headers to include in the request. Defaults to None.
            verify (bool, optional): Whether to verify the server's TLS certificate. Defaults to True.
            proxies (dict, optional): Proxies to use for the request. Defaults to None.
            **_ (dict): Additional arguments.
        Raises:
            ValueError: If no token endpoint is set for auto_refresh.
            InsecureTransportError: If the token URL is not secure.
            AuthenticationError: If the server requests new authorization.
            TemporaryAuthenticationError: If the token could not be refreshed due to a temporary server failure.
            RetrievalError: If the status code from the server is not recognized.
        Returns:
            dict: The new tokens.
        """
        LOG.info('Refreshing tokens')
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        # Store old refresh token in case no new one is given
        # First try to get from the current token property, then fall back to stored token
        if refresh_token is None:
            refresh_token = self.refresh_token
            # If still None, try to get from the token dict directly
            if refresh_token is None and self.token is not None:
                refresh_token = self.token.get('refresh_token')
        
        if not refresh_token:
            raise AuthenticationError('No refresh token available. Please log in again.')

        # Close any idle connections to prevent reusing stale connections
        # This helps prevent "Remote end closed connection without response" errors
        # that occur when trying to reuse a connection that the server has closed
        try:
            # Get the HTTPAdapter and close idle connections in the pool
            adapter = self.get_adapter(token_url)
            if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                # Clear idle connections from the pool
                adapter.poolmanager.clear()
                LOG.debug("Cleared connection pool before token refresh")
        except Exception as e:
            # If clearing fails, log but continue - not critical
            LOG.debug("Could not clear connection pool: %s", str(e))

        resolver = AuthConfigResolver(
            "volkswagen",
            hardcoded_client_id=self.client_id,
            hardcoded_qmauth_secret=_QM_SECRET,
            hardcoded_qmauth_client_id=_QM_CLIENT_ID,
            hardcoded_token_url=_CARIAD_TOKEN_URL,
        )

        # Create headers matching the examples format
        tHeaders = CaseInsensitiveDict(
            _cariad_token_headers(
                'Volkswagen/3.61.0-android/14',
                qmauth_secret=resolver.qmauth_secret(),
                qmauth_client_id=resolver.qmauth_client_id(),
            )
        )
        # Connection and Accept-Encoding are set by default by requests; ensure Keep-Alive
        tHeaders['Connection'] = 'keep-alive'

        client_id_chain = resolver.oauth_client_id_chain()

        # Use a shorter timeout for token refresh to prevent stale connection issues
        # Token endpoints should respond quickly; 30 seconds is more than enough
        # This prevents holding connections open for 180 seconds which can lead to
        # "Remote end closed connection without response" errors
        if timeout is None:
            timeout = 30

        last_error: AuthenticationError | None = None
        for idx, client_id in enumerate(client_id_chain):
            body = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            }

            token_response = self.post(
                token_url,
                data=body,
                headers=tHeaders,
                timeout=timeout,
                verify=verify,
                withhold_token=True,
                proxies=proxies,
            )

            if token_response.status_code == requests.codes['ok']:
                if idx > 0:
                    LOG.info(
                        "Token refresh (volkswagen): fallback client_id #%d "
                        "succeeded — primary candidates 4xx'd",
                        idx,
                    )
                new_token = self.parse_from_body(token_response.text)
                if new_token is not None and "refresh_token" not in new_token:
                    LOG.debug("No new refresh token given. Re-using old.")
                    new_token["refresh_token"] = refresh_token
                    self.token = new_token
                LOG.debug("Successfully refreshed tokens")
                return new_token

            # 4xx on non-last candidate: retry with next client_id
            if 400 <= token_response.status_code < 500 and idx < len(client_id_chain) - 1:
                LOG.debug(
                    "Token refresh (volkswagen) client_id %s..%s rejected "
                    "(HTTP %d) — trying next candidate",
                    client_id[:8], client_id[-4:],
                    token_response.status_code,
                )
                last_error = AuthenticationError(
                    'Refreshing tokens failed: Server requests new authorization. Please log in again.'
                )
                continue

            # 4xx on last candidate (or non-retriable): raise immediately
            if token_response.status_code == requests.codes['unauthorized']:
                LOG.error('Token refresh failed with 401 - server requests new authorization. Refresh token may be expired or invalid.')
                raise AuthenticationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
            if 400 <= token_response.status_code < 500:
                LOG.error('Token refresh failed with %d - server requests new authorization.', token_response.status_code)
                raise AuthenticationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
            if token_response.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
                raise TemporaryAuthenticationError(f'Token could not be refreshed due to temporary WeConnect failure: {token_response.status_code}')

            raise RetrievalError(f'Status Code from WeConnect while refreshing tokens was: {token_response.status_code}')

        raise last_error or AuthenticationError(
            "Token refresh: all client_id candidates exhausted"
        )
