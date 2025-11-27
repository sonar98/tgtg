# Copied and modified from https://github.com/ahivert/tgtg-python

import json
import logging
import random
import re
import time
import uuid
from datetime import datetime
from http import HTTPStatus
from urllib.parse import urljoin, urlsplit
import secrets

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Assuming tgtg_scanner.errors exists in the execution environment.
# If not, define placeholder exception classes.
try:
    from tgtg_scanner.errors import (
        TgtgAPIError,
        TGTGConfigurationError,
        TgtgLoginError,
        TgtgPollingError,
    )
except ImportError:
    class TgtgAPIError(Exception): pass
    class TGTGConfigurationError(Exception): pass
    class TgtgLoginError(Exception): pass
    class TgtgPollingError(Exception): pass


log = logging.getLogger("tgtg")
BASE_URL = "https://apptoogoodtogo.com/api/"
DATADOME_SDK_URL = "https://api-sdk.datadome.co/sdk/"
API_ITEM_ENDPOINT = "item/v9/"
FAVORITE_ITEM_ENDPOINT = "user/favorite/v1/{}/update"
AUTH_BY_EMAIL_ENDPOINT = "auth/v5/authByEmail"
AUTH_POLLING_ENDPOINT = "auth/v5/authByRequestPollingId"
SIGNUP_BY_EMAIL_ENDPOINT = "auth/v5/signUpByEmail"
REFRESH_ENDPOINT = "token/v1/refresh"
ACTIVE_ORDER_ENDPOINT = "order/v8/active"
INACTIVE_ORDER_ENDPOINT = "order/v8/inactive"
CREATE_ORDER_ENDPOINT = "order/v8/create/"
ABORT_ORDER_ENDPOINT = "order/v8/{}/abort"
ORDER_STATUS_ENDPOINT = "order/v8/{}/status"
API_BUCKET_ENDPOINT = "discover/v1/bucket"
MANUFACTURERITEM_ENDPOINT = "manufactureritem/v2/"
USER_AGENTS = [
    "TGTG/{} Dalvik/2.1.0 (Linux; U; Android 9; Nexus 5 Build/M4B30Z)",
    "TGTG/{} Dalvik/2.1.0 (Linux; U; Android 10; SM-G935F Build/NRD90M)",
    "TGTG/{} Dalvik/2.1.0 (Linux; Android 12; SM-G920V Build/MMB29K)",
]
DEFAULT_ACCESS_TOKEN_LIFETIME = 3600 * 4  # 4 hours
DEFAULT_MAX_POLLING_TRIES = 24  # 24 * POLLING_WAIT_TIME = 2 minutes
DEFAULT_POLLING_WAIT_TIME = 5  # Seconds
DEFAULT_APK_VERSION = "24.11.0"

APK_RE_SCRIPT = re.compile(r"AF_initDataCallback\({key:\s*'ds:5'.*?data:([\s\S]*?), sideChannel:.+<\/script")


class TgtgSession(requests.Session):
    http_adapter = HTTPAdapter(
        max_retries=Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1,
        )
    )

    correlation_id = str(uuid.uuid4())

    def __init__(
        self,
        user_agent: str | None = None,
        language: str = "en-UK",
        timeout: int | None = None,
        proxies: dict | None = None,
        datadome_cookie: str | None = None,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.mount("https://", self.http_adapter)
        self.mount("http://", self.http_adapter)
        self.headers = {
            "accept-language": language,
            "accept": "application/json",
            "content-type": "application/json; charset=utf-8",
            "Accept-Encoding": "gzip",
            "x-correlation-id": self.correlation_id,
        }
        if user_agent:
            self.headers["user-agent"] = user_agent
        self.timeout = timeout
        if proxies:
            self.proxies = proxies
        if datadome_cookie:
            self.cookies.set("datadome", datadome_cookie)

    def post(self, *args, access_token: str | None = None, **kwargs) -> requests.Response:
        if "headers" not in kwargs:
            kwargs["headers"] = self.headers
        if access_token:
            kwargs["headers"]["authorization"] = f"Bearer {access_token}"
        return super().post(*args, **kwargs)

    def send(self, request, **kwargs):
        for key in ["timeout", "proxies"]:
            val = kwargs.get(key)
            if val is None and hasattr(self, key):
                kwargs[key] = getattr(self, key)
        return super().send(request, **kwargs)


class TgtgClient:
    def __init__(
        self,
        base_url=BASE_URL,
        email=None,
        access_token=None,
        refresh_token=None,
        datadome_cookie=None,
        apk_version=None,
        user_agent=None,
        language="en-GB",
        proxies=None,
        timeout=None,
        access_token_lifetime=DEFAULT_ACCESS_TOKEN_LIFETIME,
        max_polling_tries=DEFAULT_MAX_POLLING_TRIES,
        polling_wait_time=DEFAULT_POLLING_WAIT_TIME,
        device_type="ANDROID",
    ):
        if base_url != BASE_URL:
            log.warning("Using custom tgtg base url: %s", base_url)

        self.base_url = base_url

        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.datadome_cookie = datadome_cookie

        self.last_time_token_refreshed = None
        self.access_token_lifetime = access_token_lifetime
        self.max_polling_tries = max_polling_tries
        self.polling_wait_time = polling_wait_time

        self.device_type = device_type
        self.apk_version = apk_version
        self.fixed_user_agent = user_agent
        self.user_agent = user_agent
        self.language = language
        self.proxies = proxies
        self.timeout = timeout
        self.session = None

        self.captcha_error_count = 0

    def __del__(self) -> None:
        if self.session:
            self.session.close()

    def _get_url(self, path) -> str:
        return urljoin(self.base_url, path)

    def _create_session(self) -> TgtgSession:
        if not self.user_agent:
            self.user_agent = self._get_user_agent()
        return TgtgSession(
            self.user_agent,
            self.language,
            self.timeout,
            self.proxies,
            self.datadome_cookie,
        )

    def get_credentials(self) -> dict:
        self.login()
        return {
            "email": self.email,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "datadome_cookie": self.datadome_cookie,
        }
        
    def _get_datadome_cookie(self, request_url: str) -> str:
        log.info("Fetching new Datadome cookie...")
        apk_version = self.apk_version or DEFAULT_APK_VERSION
        payload = {
            "cid": secrets.token_hex(32),
            "ddk": "1D42C2CA6131C526E09F294FE96F94", "request": request_url,
            "ua": self.user_agent, "events": json.dumps([{"id": 1, "message": "response validation", "source": "sdk", "date": int(time.time() * 1000)}]),
            "inte": "android-java-okhttp", "ddv": "3.0.4", "ddvc": apk_version,
            "os": "Android", "osr": "14", "osn": "UPSIDE_DOWN_CAKE", "osv": "34",
            "screen_x": 1440, "screen_y": 3120, "screen_d": 3.5,
            "camera": '{"auth":"true", "info":"{\\"front\\":\\"2000x1500\\",\\"back\\":\\"5472x3648\\"}"}',
            "mdl": "Pixel 7 Pro", "prd": "Pixel 7 Pro", "mnf": "Google", "dev": "cheetah",
            "hrd": "GS201", "fgp": "google/cheetah/cheetah:14/UQ1A.240105.004/10814564:user/release-keys",
            "tgs": "release-keys", "d_ifv": secrets.token_hex(16),
        }
        headers = {"User-Agent": "okhttp/5.1.0", "Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(DATADOME_SDK_URL, data=payload, headers=headers, timeout=self.timeout, proxies=self.proxies)
        response.raise_for_status()
        return response.json()["cookie"]

    def _post(self, path, **kwargs) -> requests.Response:
        if not self.session:
            self.session = self._create_session()

        request_url = self._get_url(path)
        response = self.session.post(request_url, access_token=self.access_token, **kwargs)

        if response.status_code in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            self.captcha_error_count = 0
            # Don't use .get() here to avoid the conflict error. The session manages the cookie.
            # We only need to interact manually when there's a 403 error.
            return response

        if response.status_code == 403:
            log.warning("Received 403. Attempting to fetch a new Datadome cookie.")
            try:
                new_cookie = self._get_datadome_cookie(request_url)
                self.datadome_cookie = new_cookie

                # --- CORRECTED COOKIE CLEARING LOGIC ---
                # Create a copy of the list to iterate over, as we will be modifying the cookie jar
                cookies_to_remove = [c for c in list(self.session.cookies) if c.name == 'datadome']
                for cookie in cookies_to_remove:
                    # To remove a cookie from a RequestsCookieJar, you can't use 'del' if there are duplicates.
                    # The most reliable way is to set its value to None and expire it.
                    self.session.cookies.set(
                        name=cookie.name,
                        value=None,
                        domain=cookie.domain,
                        path=cookie.path,
                        expires=0 # A time in the past
                    )
                
                # Now that the jar is clean of old datadome cookies, set the new one.
                self.session.cookies.set("datadome", new_cookie)

                log.warning(self.datadome_cookie)
                log.info("Retrying request with new Datadome cookie.")
                log.warning(request_url)
                log.warning(access_token)
                
                response = self.session.post(request_url, access_token=self.access_token, **kwargs)

                if response.status_code in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
                    self.captcha_error_count = 0
                    return response
                
                if response.status_code != 403:
                    raise TgtgAPIError(response.status_code, response.content)

            except Exception as e:
                log.error(f"Failed to refresh Datadome cookie: {e}. Falling back to failsafe logic.")
                log.warning(response.status_code)

            log.debug("Datadome refresh did not solve the 403. Applying failsafe captcha logic.")
            self.captcha_error_count += 1
            if self.captcha_error_count == 1: self.user_agent = self._get_user_agent()
            elif self.captcha_error_count == 2: self.session = self._create_session()
            elif self.captcha_error_count == 4: self.datadome_cookie = None; self.session = self._create_session()
            elif self.captcha_error_count >= 10:
                log.warning("Too many captcha Errors! Sleeping for 10 minutes..."); time.sleep(10 * 60)
                log.info("Retrying ..."); self.captcha_error_count = 0; self.session = self._create_session()
            time.sleep(1)
            return self._post(path, **kwargs)

        raise TgtgAPIError(response.status_code, response.content)
        log.warning(response.content)
    

    def _get_user_agent(self) -> str:
        if self.fixed_user_agent: return self.fixed_user_agent
        version = DEFAULT_APK_VERSION
        if self.apk_version is None:
            try: version = self.get_latest_apk_version()
            except Exception: log.warning("Failed to get latest APK version!")
        else: version = self.apk_version
        log.debug("Using APK version %s.", version)
        return random.choice(USER_AGENTS).format(version)

    @staticmethod
    def get_latest_apk_version() -> str:
        response = requests.get("https://play.google.com/store/apps/details?id=com.app.tgtg&hl=en&gl=US", timeout=30)
        match = APK_RE_SCRIPT.search(response.text)
        if not match: raise TgtgAPIError("Failed to get latest APK version from Google Play Store.")
        data = json.loads(match.group(1))
        return data[1][2][140][0][0][0]

    @property
    def _already_logged(self) -> bool:
        return bool(self.access_token and self.refresh_token)

    def _refresh_token(self) -> None:
        if (self.last_time_token_refreshed and (datetime.now() - self.last_time_token_refreshed).seconds <= self.access_token_lifetime): return
        response = self._post(REFRESH_ENDPOINT, json={"refresh_token": self.refresh_token})
        self.access_token = response.json().get("access_token")
        self.refresh_token = response.json().get("refresh_token")
        self.last_time_token_refreshed = datetime.now()

    def login(self) -> None:
        if not (self.email or self.access_token and self.refresh_token): raise TGTGConfigurationError("You must provide at least email or access_token and refresh_token")
        if self._already_logged: self._refresh_token()
        else:
            log.info("Starting login process ...")
            response = self._post(AUTH_BY_EMAIL_ENDPOINT, json={"device_type": self.device_type, "email": self.email})
            first_login_response = response.json()
            if first_login_response["state"] == "TERMS": raise TgtgPollingError(f"This email {self.email} is not linked to a tgtg account. Please signup with this email first.")
            if first_login_response.get("state") == "WAIT": self.start_polling(first_login_response.get("polling_id"))
            else: raise TgtgLoginError(response.status_code, response.content)

    def start_polling(self, polling_id) -> None:
        for _ in range(self.max_polling_tries):
            response = self._post(AUTH_POLLING_ENDPOINT, json={"device_type": self.device_type, "email": self.email, "request_polling_id": polling_id})
            if response.status_code == HTTPStatus.ACCEPTED:
                log.warning("Check your mailbox on PC to continue... (Mailbox on mobile won't work, if you have installed tgtg app.)")
                time.sleep(self.polling_wait_time); continue
            if response.status_code == HTTPStatus.OK:
                log.info("Logged in!")
                login_response = response.json()
                self.access_token = login_response.get("access_token"); self.refresh_token = login_response.get("refresh_token")
                self.last_time_token_refreshed = datetime.now(); return
        raise TgtgPollingError("Max polling retries reached. Try again.")

    def get_items(self, *, latitude=0.0, longitude=0.0, radius=21, page_size=20, page=1, discover=False, favorites_only=True, item_categories=None, diet_categories=None, pickup_earliest=None, pickup_latest=None, search_phrase=None, with_stock_only=False, hidden_only=False, we_care_only=False) -> list[dict]:
        self.login()
        data = { "origin": {"latitude": latitude, "longitude": longitude}, "radius": radius, "page_size": page_size, "page": page, "discover": discover, "favorites_only": favorites_only, "item_categories": item_categories if item_categories else [], "diet_categories": diet_categories if diet_categories else [], "pickup_earliest": pickup_earliest, "pickup_latest": pickup_latest, "search_phrase": search_phrase if search_phrase else None, "with_stock_only": with_stock_only, "hidden_only": hidden_only, "we_care_only": we_care_only }
        response = self._post(API_ITEM_ENDPOINT, json=data)
        return response.json().get("items", [])

    def get_item(self, item_id: str) -> dict:
        self.login()
        response = self._post(f"{API_ITEM_ENDPOINT}/{item_id}", json={"origin": None})
        return response.json()

    def get_favorites(self) -> list[dict]:
        items = []; page = 1; page_size = 100
        while True:
            new_items = self.get_items(favorites_only=True, page_size=page_size, page=page)
            items += new_items
            if len(new_items) < page_size: break
            page += 1
        return items

    def set_favorite(self, item_id: str, is_favorite: bool) -> None:
        self.login()
        self._post(FAVORITE_ITEM_ENDPOINT.format(item_id), json={"is_favorite": is_favorite})

    def create_order(self, item_id: str, item_count: int) -> dict[str, str]:
        self.login()
        response = self._post(f"{CREATE_ORDER_ENDPOINT}/{item_id}", json={"item_count": item_count})
        if response.json().get("state") != "SUCCESS": raise TgtgAPIError(response.status_code, response.content)
        return response.json().get("order", {})

    def get_order_status(self, order_id: str) -> dict[str, str]:
        self.login()
        response = self._post(ORDER_STATUS_ENDPOINT.format(order_id))
        return response.json()

    def abort_order(self, order_id: str) -> None:
        self.login()
        response = self._post(ABORT_ORDER_ENDPOINT.format(order_id), json={"cancel_reason_id": 1})
        if response.json().get("state") != "SUCCESS": raise TgtgAPIError(response.status_code, response.content)

    def get_manufactureritems(self) -> dict:
        self.login()
        response = self._post(MANUFACTURERITEM_ENDPOINT, json={"action_types_accepted": ["QUERY"], "display_types_accepted": ["LIST", "FILL"], "element_types_accepted": ["ITEM", "HIGHLIGHTED_ITEM", "MANUFACTURER_STORY_CARD", "DUO_ITEMS", "DUO_ITEMS_V2", "TEXT", "PARCEL_TEXT", "NPS", "SMALL_CARDS_CAROUSEL", "ITEM_CARDS_CAROUSEL"]})
        return response.json()
