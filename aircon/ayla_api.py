"""
Simple implementation of the Ayla networks API

Devices use the Ayla networks IoT API to communicate with the device.  Documentation can be
found at:
 - https://developer.aylanetworks.com/apibrowser/
 - https://docs.aylanetworks.com/cloud-services/api-browser/
"""

import aiohttp
import requests
import base64
from datetime import datetime, timedelta
from logging import getLogger
from typing import Dict, List, Optional

from .aircon import AcDevice
from .app_mappings import (
    AYLA_USER_SERVERS,
    AYLA_DEVICES_SERVERS,
    SECRET_MAP,
    SECRET_ID_MAP,
    SECRET_ID_EXTRA_MAP,
)
from .error import AuthExpiring, AuthFailed, NotAuthorized

_session = None

_LOGGER = getLogger(__name__)


def get_ayla_api(
    appcode: str,
    username: str,
    password: str,
    websession: Optional[aiohttp.ClientSession] = None,
):
    """Get an AylaApi object"""
    return AylaApi(appcode, username, password, websession=websession)


class AylaApi:
    """Simple Ayla Networks API wrapper"""

    def __init__(
        self,
        appcode: str,
        email: str,
        password: str,
        websession: Optional[aiohttp.ClientSession] = None,
    ):
        self._email = email
        self._password = password
        self._access_token = None  # type: Optional[str]
        self._refresh_token = None  # type: Optional[str]
        self._auth_expiration = None  # type: Optional[datetime]
        self._is_authed = False  # type: bool
        self._appcode = appcode
        self.websession = websession

        self._setup_appid_and_appsecret(appcode)

    def _setup_appid_and_appsecret(self, app: str) -> str:
        if app in SECRET_ID_MAP:
            app_prefix = SECRET_ID_MAP[app]
        else:
            app_prefix = "a-Hisense-{}-field".format(app)

        if app in SECRET_ID_EXTRA_MAP:
            self._app_id = "-".join((app_prefix, SECRET_ID_EXTRA_MAP[app], "id"))
        else:
            self._app_id = "-".join((app_prefix, "id"))

        secret = (
            base64.b64encode(SECRET_MAP[app])
            .decode("utf-8")
            .rstrip("=")
            .replace("+", "-")
            .replace("/", "_")
        )
        self._app_secret = "-".join((app_prefix, secret))

    @property
    def _user_server(self) -> str:
        """Returns user server URL"""
        region = self._appcode[-2:]
        if region not in AYLA_USER_SERVERS:
            region = "us"
        return AYLA_USER_SERVERS[region]

    @property
    def device_server(self) -> str:
        """Returns device server URL"""
        region = self._appcode[-2:]
        if region not in AYLA_USER_SERVERS:
            region = "us"
        return AYLA_DEVICES_SERVERS[region]

    def ensure_session(self) -> aiohttp.ClientSession:
        """Ensure that we have an aiohttp ClientSession"""
        if self.websession is None:
            self.websession = aiohttp.ClientSession()
        return self.websession

    @property
    def _login_data(self) -> Dict[str, Dict]:
        """Prettily formatted data for the login flow"""
        return {
            "user": {
                "email": self._email,
                "password": self._password,
                "application": {
                    "app_id": self._app_id,
                    "app_secret": self._app_secret,
                },
            }
        }

    def _set_credentials(self, status_code: int, login_result: Dict):
        """Update the internal credentials store."""
        if status_code == 404:
            raise AuthFailed(
                login_result["error"]["message"]
                + " (Confirm app_id and app_secret are correct)"
            )
        elif status_code == 401:
            raise AuthFailed(login_result["error"]["message"])

        self._access_token = login_result["access_token"]
        self._refresh_token = login_result["refresh_token"]
        self._auth_expiration = datetime.now() + timedelta(
            seconds=login_result["expires_in"]
        )
        self._is_authed = True

    def sign_in(self):
        """Authenticate to Ayla API synchronously."""
        login_data = self._login_data
        resp = requests.post(
            f"https://{self._user_server:s}/users/sign_in.json", json=login_data
        )
        self._set_credentials(resp.status_code, resp.json())

    def refresh_auth(self):
        """Refresh the authentication synchronously"""
        refresh_data = {"user": {"refresh_token": self._refresh_token}}
        resp = requests.post(
            f"https://{self._user_server:s}/users/refresh_token.json", json=refresh_data
        )
        self._set_credentials(resp.status_code, resp.json())

    async def async_sign_in(self):
        """Authenticate to Ayla API synchronously."""
        session = self.ensure_session()
        login_data = self._login_data
        async with session.post(
            f"https://{self._user_server:s}/users/sign_in.json", json=login_data
        ) as resp:
            self._set_credentials(resp.status, await resp.json())

    async def async_refresh_auth(self):
        """Refresh the authentication synchronously."""
        session = self.ensure_session()
        refresh_data = {"user": {"refresh_token": self._refresh_token}}
        async with session.post(
            f"https://{self._user_server:s}/users/refresh_token.json", json=refresh_data
        ) as resp:
            self._set_credentials(resp.status, await resp.json())

    @property
    def sign_out_data(self) -> Dict:
        """Payload for the sign_out call"""
        return {"user": {"access_token": self._access_token}}

    def _clear_auth(self):
        """Clear authentication state"""
        self._is_authed = False
        self._access_token = None
        self._refresh_token = None
        self._auth_expiration = None

    def sign_out(self):
        """Sign out and invalidate the access token"""
        requests.post(
            f"https://{self._user_server:s}/users/sign_out.json",
            json=self.sign_out_data,
        )
        self._clear_auth()

    async def async_sign_out(self):
        """Sign out and invalidate the access token"""
        session = self.ensure_session()
        async with session.post(
            f"https://{self._user_server:s}/users/sign_out.json",
            json=self.sign_out_data,
        ) as _:
            pass
        self._clear_auth()

    @property
    def auth_expiration(self) -> Optional[datetime]:
        """When does the auth expire"""
        if not self._is_authed:
            return None
        elif (
            self._auth_expiration is None
        ):  # This should not happen, but let's be ready if it does...
            raise NotAuthorized("Invalid state.  Please reauthorize.")
        else:
            return self._auth_expiration

    @property
    def token_expired(self) -> bool:
        """Return true if the token has already expired"""
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration

    @property
    def token_expiring_soon(self) -> bool:
        """Return true if the token will expire soon"""
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration - timedelta(
            seconds=600
        )  # Prevent timeout immediately following

    def check_auth(self, raise_expiring_soon=True):
        """Confirm authentication status"""
        if not self._access_token or not self._is_authed or self.token_expired:
            self._is_authed = False
            raise NotAuthorized()
        elif raise_expiring_soon and self.token_expiring_soon:
            raise AuthExpiring()

    @property
    def auth_header(self) -> Dict[str, str]:
        self.check_auth()
        return {"Authorization": f"auth_token {self._access_token:s}"}

    def _get_headers(self, fn_kwargs) -> Dict[str, str]:
        """
        Extract the headers element from fn_kwargs, removing it if it exists
        and updating with self.auth_header.
        """
        try:
            headers = fn_kwargs["headers"]
        except KeyError:
            headers = {}
        else:
            del fn_kwargs["headers"]
        headers.update(self.auth_header)
        return headers

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = self._get_headers(kwargs)
        return requests.request(method, url, headers=headers, **kwargs)

    async def async_request(self, http_method: str, url: str, **kwargs):
        session = self.ensure_session()
        headers = self._get_headers(kwargs)
        return session.request(http_method, url, headers=headers, **kwargs)

    def list_devices(self) -> List[Dict]:
        resp = self.request("get", f"https://{self.device_server:s}/apiv1/devices.json")
        devices = resp.json()
        if resp.status_code == 401:
            raise AuthFailed(devices["error"]["message"])
        return [d["device"] for d in devices]

    async def async_list_devices(self) -> List[Dict]:
        async with await self.async_request(
            "get", f"https://{self.device_server:s}/apiv1/devices.json"
        ) as resp:
            devices = await resp.json()
            if resp.status == 401:
                raise AuthFailed(devices["error"]["message"])
        return [d["device"] for d in devices]

    def get_device_data(self) -> List[AcDevice]:
        devices = [AcDevice(self, d) for d in self.list_devices()]
        for device in devices:
            device.get_lan_config()
        return devices

    async def async_get_devices(self) -> List[AcDevice]:
        devices = [AcDevice(self, d) for d in await self.async_list_devices()]
        for device in devices:
            await device.async_get_lan_config()
        return devices
