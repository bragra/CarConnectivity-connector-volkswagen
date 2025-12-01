"""
Module implements the WeConnect Session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import json
import logging
import secrets
import keyring
import threading

from urllib.parse import parse_qsl, urlparse

import requests
from requests.models import CaseInsensitiveDict

from oauthlib.common import add_params_to_uri, generate_nonce, to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from carconnectivity.errors import AuthenticationError, RetrievalError, TemporaryAuthenticationError

from carconnectivity_connectors.volkswagen.auth.openid_session import AccessType
from carconnectivity_connectors.volkswagen.auth.vw_web_session import VWWebSession

if TYPE_CHECKING:
    from typing import Tuple, Dict


LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.volkswagen.auth")
LOG.setLevel(logging.DEBUG)  # Enable detailed logging for debugging

class WeConnectSession(VWWebSession):
    """
    WeConnectSession class handles the authentication and session management for Volkswagen's WeConnect service.
    """
    def __init__(self, session_user, **kwargs) -> None:
        """Initialize WeConnectSession while maintaining backward compatibility"""
        LOG.info("Initializing WeConnectSession for user: %s", session_user)
        # Maintain original parameter defaults for backward compatibility
        kwargs.setdefault('client_id', 'a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com')
        kwargs.setdefault('refresh_url', 'https://identity.vwgroup.io/oidc/v1/token')
        kwargs.setdefault('scope', 'openid profile badge cars dealers vin')
        kwargs.setdefault('redirect_uri', 'weconnect://authenticated')
        kwargs.setdefault('state', None)
        
        super(WeConnectSession, self).__init__(session_user=session_user, **kwargs)
        LOG.debug("Session initialized with client_id: %s", self.client_id)
        self._token_lock = threading.Lock()
        self._monitor_active = False
        self._monitor_thread = None
        self._load_tokens()

        # Start token monitoring thread
        self._start_token_monitor()

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'Volkswagen/3.51.1-android/14',
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
        LOG.debug("Adding weconnect-trace-id header: %s", we_connect_trace_id)
        
        with self._token_lock:
            return super(WeConnectSession, self).request(
                method, url, headers=headers, data=data, withhold_token=withhold_token,
                access_type=access_type, token=token, timeout=timeout, **kwargs
            )

    def login(self):
        """Authenticate with WeConnect service with comprehensive error handling"""
        super(WeConnectSession, self).login()
        max_attempts = 3
        last_error = None
        
        for attempt in range(1, max_attempts + 1):
            try:
                # retrieve authorization URL
                authorization_url_str: str = self.authorization_url(url='https://identity.vwgroup.io/oidc/v1/authorize')
                # perform web authentication
                response = self.do_web_auth(authorization_url_str)
                # fetch tokens from web authentication response
                self.fetch_tokens('https://emea.bff.cariad.digital/user-login/login/v1',
                                authorization_response=response)
                return  # Success
            except TemporaryAuthenticationError as e:
                last_error = e
                LOG.warning(f"Login attempt {attempt} failed (temporary error), retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
            except AuthenticationError as e:
                last_error = e
                LOG.error(f"Login attempt {attempt} failed (authentication error)")
                break
            except requests.exceptions.RequestException as e:
                last_error = TemporaryAuthenticationError(f"Network error during login: {str(e)}")
                LOG.warning(f"Login attempt {attempt} failed (network error), retrying...")
                time.sleep(2 ** attempt)
            except Exception as e:
                last_error = AuthenticationError(f"Unexpected error during login: {str(e)}")
                LOG.error(f"Login attempt {attempt} failed (unexpected error)")
                break
        
        # If we get here, all attempts failed
        LOG.error("All login attempts failed")
        if last_error:
            raise last_error
        raise AuthenticationError("Login failed after multiple attempts")

    def refresh(self) -> None:
        """Refresh authentication tokens with comprehensive error handling"""
        max_attempts = 2
        last_error = None
        
        for attempt in range(1, max_attempts + 1):
            try:
                # First try normal refresh
                self.refresh_tokens(
                    'https://emea.bff.cariad.digital/login/v1/idk/token',
                )
                return  # Success
            except TemporaryAuthenticationError as e:
                last_error = e
                LOG.warning(f"Refresh attempt {attempt} failed (temporary error), retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
            except AuthenticationError as e:
                last_error = e
                LOG.error("Refresh token invalid, attempting full login...")
                try:
                    self.clear_tokens()
                    self.login()
                    return  # Success via full login
                except Exception as e:
                    last_error = e
                    break
            except requests.exceptions.RequestException as e:
                last_error = TemporaryAuthenticationError(f"Network error during refresh: {str(e)}")
                LOG.warning(f"Refresh attempt {attempt} failed (network error), retrying...")
                time.sleep(2 ** attempt)
            except Exception as e:
                last_error = AuthenticationError(f"Unexpected error during refresh: {str(e)}")
                LOG.error(f"Refresh attempt {attempt} failed (unexpected error)")
                break
        
        # If we get here, all attempts failed
        LOG.error("All refresh attempts failed")
        if last_error:
            raise last_error
        raise AuthenticationError("Refresh failed after multiple attempts")

    def _start_token_monitor(self) -> None:
        """Start background thread to monitor token expiration"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
            
        self._monitor_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_tokens,
            daemon=True,
            name="TokenMonitor"
        )
        self._monitor_thread.start()
        LOG.debug("Started token monitoring thread")
        
    def _monitor_tokens(self) -> None:
        """Background thread to check token expiration and refresh when needed"""
        while self._monitor_active:
            try:
                with self._token_lock:
                    if not self.token:
                        time.sleep(10)
                        continue
                        
                    expires_in = int(self.token.get('expires_in', 0))
                    
                # Refresh if token will expire in next 2 minutes
                if 0 < expires_in < 120:
                    LOG.info("Proactively refreshing expiring token")
                    try:
                        self.refresh()
                    except Exception as e:
                        LOG.error(f"Proactive token refresh failed: {str(e)}")
                        
                # Sleep for half the remaining time or 30s minimum
                sleep_time = max(30, expires_in // 2) if expires_in > 0 else 30
                time.sleep(sleep_time)
                
            except Exception as e:
                LOG.error(f"Token monitor error: {str(e)}")
                time.sleep(30)

    def clear_tokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.
        
        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self._monitor_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            
        with self._token_lock:
            self.token = None
            try:
                keyring.delete_password('carconnectivity_volkswagen',
                                      f'{self.session_user}_access_token')
                keyring.delete_password('carconnectivity_volkswagen',
                                      f'{self.session_user}_refresh_token')
                keyring.delete_password('carconnectivity_volkswagen',
                                      f'{self.session_user}_id_token')
                keyring.delete_password('carconnectivity_volkswagen',
                                      f'{self.session_user}_expires_at')
                LOG.debug("All tokens cleared successfully from memory and secure storage")
            except Exception as e:
                LOG.error(f"Failed to clear tokens from keyring: {str(e)}")

    def authorization_url(self, url, state=None, **kwargs) -> str:
        if state is not None:
            raise AuthenticationError('Do not provide state')
        if self.redirect_uri is None:
            raise AuthenticationError('Redirect URI is not set')

        params: list[Tuple[str, str]] = [(('redirect_uri', self.redirect_uri)),
                                         (('nonce', generate_nonce()))]

        # add required parameters redirect_uri and nonce to the authorization URL
        auth_url: str = add_params_to_uri('https://emea.bff.cariad.digital/user-login/v1/authorize', params)
        try_login_response: requests.Response = self.get(auth_url, allow_redirects=False, access_type=AccessType.NONE)  # pyright: ignore reportCallIssue
        if try_login_response.status_code != requests.codes['see_other'] or 'Location' not in try_login_response.headers:
            raise AuthenticationError('Authorization URL could not be fetched due to WeConnect failure')
        # Redirect is URL to authorize
        redirect: str = try_login_response.headers['Location']
        query: str = urlparse(redirect).query
        query_params: Dict[str, str] = dict(parse_qsl(query))
        if 'state' in query_params:
            self.state = query_params['state']

        return redirect

    def fetch_tokens(
        self,
        token_url,
        authorization_response=None,
        **_
    ):
        """
        Fetches tokens using the given token URL using the tokens from authorization response.

        Args:
            token_url (str): The URL to request the tokens from.
            authorization_response (str, optional): The authorization response containing the tokens. Defaults to None.
            **_ : Additional keyword arguments.

        Returns:
            dict: A dictionary containing the fetched tokens if successful.
            None: If the tokens could not be fetched.

        Raises:
            TemporaryAuthenticationError: If the token request fails due to a temporary WeConnect failure.
        """
        # take token from authorization response (those are stored in self.token now!)
        self.parse_from_fragment(authorization_response)

        if self.token is not None and all(key in self.token for key in ('state', 'id_token', 'access_token', 'code')):
            # Generate json body for token request
            body: str = json.dumps(
                {
                    'state': self.token['state'],
                    'id_token': self.token['id_token'],
                    'redirect_uri': self.redirect_uri,
                    'region': 'emea',
                    'access_token': self.token['access_token'],
                    'authorizationCode': self.token['code'],
                })

            request_headers: CaseInsensitiveDict = self.headers  # pyright: ignore reportAssignmentType
            request_headers['accept'] = 'application/json'

            # request tokens from token_url
            token_response = self.post(token_url, headers=request_headers, data=body, allow_redirects=False,
                                       access_type=AccessType.ID)  # pyright: ignore reportCallIssue
            if token_response.status_code != requests.codes['ok']:
                raise TemporaryAuthenticationError(f'Token could not be fetched due to temporary WeConnect failure: {token_response.status_code}')
            # parse token from response body
            token = self.parse_from_body(token_response.text)
            
            # Ensure the token is properly stored in the session
            if token is not None:
                self.token = token  # Explicitly store the token
                LOG.debug(f"Successfully fetched tokens. Access token expires in: {token.get('expires_in', 'unknown')} seconds")
                LOG.debug(f"Refresh token available: {'refresh_token' in token}")
                # Verify critical tokens are present
                if not all(key in token for key in ('access_token', 'id_token', 'refresh_token')):
                    LOG.warning("Some expected tokens are missing from the response")
            else:
                LOG.error("Token parsing returned None")

            return token
        else:
            LOG.error("Authorization response missing required tokens")
            return None

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
        # Let OAuthlib parse the token
        parsed_token = super(WeConnectSession, self).parse_from_body(token_response=fixed_token_response, state=state)
        # Ensure the token is stored in the session object
        self.token = parsed_token
        return parsed_token

    def _persist_tokens(self, new_token, old_refresh_token=None):
        """
        Persist tokens between sessions, ensuring we maintain refresh tokens.
        
        Args:
            new_token (dict): New token data
            old_refresh_token (str): Previous refresh token to preserve if needed
            
        Returns:
            dict: The final token data to store
        """
        if not new_token:
            return None
            
        # Always preserve the refresh token if we have one
        if 'refresh_token' not in new_token and old_refresh_token:
            LOG.debug('Preserving previous refresh token')
            new_token['refresh_token'] = old_refresh_token
            
        # Store the token in the session and keyring
        with self._token_lock:
            self.token = new_token
            try:
                if new_token.get('access_token'):
                    keyring.set_password('carconnectivity_volkswagen',
                                       f'{self.session_user}_access_token',
                                       new_token['access_token'])
                if new_token.get('refresh_token'):
                    keyring.set_password('carconnectivity_volkswagen',
                                       f'{self.session_user}_refresh_token',
                                       new_token['refresh_token'])
                if new_token.get('id_token'):
                    keyring.set_password('carconnectivity_volkswagen',
                                       f'{self.session_user}_id_token',
                                       new_token['id_token'])
                if new_token.get('expires_in'):
                    keyring.set_password('carconnectivity_volkswagen',
                                       f'{self.session_user}_expires_at',
                                       str(int(time.time()) + int(new_token['expires_in'])))
            except Exception as e:
                LOG.error(f"Failed to store tokens in keyring: {str(e)}")
                
        return new_token
        
    def _load_tokens(self):
        """Load tokens from secure storage if available"""
        with self._token_lock:
            try:
                access_token = keyring.get_password('carconnectivity_volkswagen',
                                                  f'{self.session_user}_access_token')
                refresh_token = keyring.get_password('carconnectivity_volkswagen',
                                                  f'{self.session_user}_refresh_token')
                id_token = keyring.get_password('carconnectivity_volkswagen',
                                             f'{self.session_user}_id_token')
                expires_at = keyring.get_password('carconnectivity_volkswagen',
                                               f'{self.session_user}_expires_at')
                
                if access_token and refresh_token and id_token:
                    self.token = {
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'id_token': id_token,
                        'expires_in': max(0, int(expires_at) - int(time.time())) if expires_at else 0
                    }
                    LOG.debug("Successfully loaded tokens from secure storage")
            except Exception as e:
                LOG.error(f"Failed to load tokens from keyring: {str(e)}")
                self.token = None
                
    def _validate_token(self, token: dict) -> bool:
            """
            Validate token structure and expiration
            
            Args:
                token: Token dictionary to validate
                
            Returns:
                bool: True if token is valid, False otherwise
            """
            try:
                if not token:
                    LOG.debug("Token validation failed: empty token")
                    return False
                    
                required_keys = {'access_token', 'refresh_token', 'id_token'}
                if not required_keys.issubset(token.keys()):
                    LOG.debug("Token validation failed: missing required fields")
                    return False
                    
                if not all(isinstance(token[k], str) and token[k] for k in required_keys):
                    LOG.debug("Token validation failed: invalid token values")
                    return False
                    
                # Check expiration if available
                if 'expires_in' in token and int(token.get('expires_in', 0)) <= 0:
                    LOG.debug("Token validation failed: token expired")
                    return False
                    
                return True
            except Exception as e:
                LOG.error(f"Token validation error: {str(e)}")
                return False
            
    def _should_refresh_token(self) -> bool:
            """
            Determine if token should be refreshed based on expiration and validity
            
            Returns:
                bool: True if token should be refreshed, False otherwise
            """
            try:
                if not self.token:
                    LOG.debug("Token refresh needed: no token available")
                    return True
                    
                if not self._validate_token(self.token):
                    LOG.debug("Token refresh needed: invalid token")
                    return True
                    
                # Refresh if token is about to expire (within 5 minutes)
                expires_in = int(self.token.get('expires_in', 0))
                if expires_in > 0 and expires_in < 300:
                    LOG.debug(f"Token refresh needed: expires in {expires_in} seconds")
                    return True
                    
                return False
            except Exception as e:
                LOG.error(f"Token refresh check error: {str(e)}")
                return True

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
        with self._token_lock:
            if not self._should_refresh_token():
                LOG.debug('Token refresh not needed - using existing valid token')
                return self.token
                
            # Store current refresh token for rotation
            old_refresh_token = self.token.get('refresh_token') if self.token else None
            
        LOG.info('Attempting to refresh tokens with proactive rotation')
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        # Validate and retrieve refresh token
        if refresh_token is None:
            refresh_token = self.refresh_token
            if refresh_token is None and self.token is not None:
                refresh_token = self.token.get('refresh_token')
        
        if not refresh_token:
            LOG.error('No refresh token available for refresh attempt')
            raise AuthenticationError('No refresh token available. Please log in again.')

        LOG.debug('Using refresh token (last 4 chars): %s', refresh_token[-4:] if refresh_token else 'None')

        # Prepare request headers and body
        tHeaders = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Volkswagen/3.51.1-android/14",
            "x-android-package-name": "com.volkswagen.weconnect",
        }

        body = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        try:
            # Request new tokens using POST with form data
            token_response = self.post(
                token_url,
                data=body,
                headers=tHeaders,
                timeout=timeout,
                verify=verify,
                proxies=proxies,
            )
            
            if token_response.status_code == requests.codes['unauthorized']:
                LOG.error('Token refresh failed with 401 - refresh token invalid or expired')
                raise AuthenticationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
            elif token_response.status_code in (requests.codes['internal_server_error'],
                                             requests.codes['service_unavailable'],
                                             requests.codes['gateway_timeout']):
                LOG.warning('Temporary server error during token refresh (status: %d)', token_response.status_code)
                raise TemporaryAuthenticationError(f'Token could not be refreshed due to temporary WeConnect failure: {token_response.status_code}')
            elif token_response.status_code == requests.codes['ok']:
                # parse new tokens from response
                new_token = self.parse_from_body(token_response.text)
                if new_token is None:
                    LOG.error('Failed to parse token response')
                    raise RetrievalError('Invalid token response format')
                
                if "refresh_token" not in new_token:
                    LOG.debug('No new refresh token provided - preserving existing one')
                    new_token["refresh_token"] = refresh_token
                else:
                    # If we got a new refresh token, invalidate the old one
                    if old_refresh_token and old_refresh_token != new_token["refresh_token"]:
                        try:
                            # Attempt to revoke old refresh token
                            revoke_body = {
                                "token": old_refresh_token,
                                "token_type_hint": "refresh_token",
                                "client_id": self.client_id
                            }
                            self.post('https://identity.vwgroup.io/oidc/v1/revoke',
                                     data=revoke_body,
                                     headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                     access_type=AccessType.NONE)
                            LOG.debug("Successfully revoked old refresh token")
                        except Exception as e:
                            LOG.warning(f"Failed to revoke old refresh token: {str(e)}")
                
                LOG.info('Token refresh successful. New access token expires in %d seconds',
                        new_token.get('expires_in', 0))
                with self._token_lock:
                    self.token = new_token
                return new_token
            else:
                LOG.error('Unexpected status code during token refresh: %d', token_response.status_code)
                raise RetrievalError(f'Unexpected status code from WeConnect: {token_response.status_code}')
        except requests.exceptions.RequestException as req_err:
            LOG.error('Request failed during token refresh: %s', str(req_err))
            raise TemporaryAuthenticationError(f'Network error during token refresh: {str(req_err)}')
