"""
NFAuthenticationKey script.

Copyright (C) 2020 Stefano Gottardo
SPDX-License-Identifier: GPL-3.0-only
See LICENSE.md for more information.
"""

# /// script
# requires-python = ">=3.9,<4"
# dependencies = [
#   "websocket-client",
#   "pycryptodome",
# ]
# ///

from __future__ import annotations

import base64
import contextlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import websocket
from Crypto.Cipher import AES
from Crypto.Util import Padding

IS_MACOS = platform.system().lower() == "darwin"

LINUX_BROWSERS = [
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-unstable",
    "chromium",
    "chromium-browser",
    "brave-browser",
]
MACOS_BROWSERS = ["Google Chrome", "Chromium", "Brave Browser"]

# Script configuration
BROWSER_PATH = "* Remove me and specify here the browser path, only if not recognized *"
DEBUG_PORT = 9222
LOCALHOST_ADDRESS = "127.0.0.1"
URL = "https://www.netflix.com/login"


class Main:
    app_version = "1.1.8"
    _msg_id = 0
    _ws = None

    def __init__(self, browser_temp_path):
        show_msg("")
        show_msg(
            TextFormat.BOLD
            + f"NFAuthentication Key for Linux/MacOS (Version {self.app_version})",
            TextFormat.COL_LIGHT_BLUE,
        )
        show_msg("")
        show_msg("Disclaimer:")
        show_msg(
            'This script and source code available on GitHub are provided "as is" without warranty of any kind, either express or implied. Use at your own risk. The use of the software is done at your own discretion and risk with the agreement that you will be solely responsible for any damage resulting from such activities and you are solely responsible for adequate data protection.',
            TextFormat.COL_GREEN,
        )
        show_msg("")
        browser_proc = None
        try:
            input_msg(
                'Press "ENTER" key to accept the disclaimer and start, or "CTRL+C" to cancel',
                TextFormat.BOLD,
            )
            browser_proc = open_browser(browser_temp_path)
            self.operations()
        except Warning as exc:
            show_msg(str(exc), TextFormat.COL_LIGHT_RED)
            if browser_proc:
                browser_proc.terminate()
        except Exception as exc:
            show_msg("An error is occurred:\r\n" + str(exc), TextFormat.COL_LIGHT_RED)
            import traceback

            show_msg(traceback.format_exc())
            if browser_proc:
                browser_proc.terminate()
        finally:
            with contextlib.suppress(Exception):
                if self._ws:
                    self._ws.close()

    def operations(self):
        show_msg("Establish connection with the browser... please wait")
        self.get_browser_debug_endpoint()
        self.ws_request("Network.enable")
        self.ws_request("Page.enable")
        show_msg("Opening login webpage... please wait")
        self.ws_request("Page.navigate", {"url": URL})

        self.ws_wait_event("Page.domContentEventFired")

        show_msg(
            "Please login in to website now ...waiting for you to finish...",
            TextFormat.COL_LIGHT_BLUE,
        )
        if not self.wait_user_logged():
            msg = "You have exceeded the time available for the login. Restart the operations."
            raise Warning(msg)

        self.ws_wait_event("Network.loadingFinished")

        # Verify that falcorCache data exist, this data exist only when logged
        show_msg("Verification of data in progress... please wait")
        params = {"expression": "document.documentElement.outerHTML"}
        html_page = self.ws_request("Runtime.evaluate", params)["result"]["value"]
        react_context = extract_json(html_page, "reactContext")
        if react_context is None:
            # An error is happened in the reactContext extraction? try go on
            show_msg(
                "Error failed to check account membership status, try a simple check",
                TextFormat.COL_LIGHT_RED,
            )
            if "falcorCache" not in html_page:
                raise Warning("Error unable to find falcorCache data.")
        else:
            # Check the membership status
            membership_status = react_context["models"]["userInfo"]["data"][
                "membershipStatus"
            ]
            if membership_status != "CURRENT_MEMBER":
                show_msg(
                    f"The account membership status is: {membership_status}",
                    TextFormat.COL_LIGHT_RED,
                )
                msg = "Your login can not be used. The possible causes are account not confirmed/renewed/reactivacted."
                raise Warning(msg)

        self.ws_wait_event("Page.loadEventFired")

        show_msg("File creation in progress... please wait")
        # Get all cookies
        cookies = self.ws_request("Network.getAllCookies").get("cookies", [])
        assert_cookies(cookies)
        # Generate a random PIN for access to "NFAuthentication.key" file
        pin = random.randint(1000, 9999)
        # Create file data structure
        data = {
            "app_name": "NFAuthenticationKey",
            "app_version": self.app_version,
            "app_system": "MacOS" if IS_MACOS else "Linux",
            "app_author": "CastagnaIT",
            "timestamp": int(
                (
                    (datetime.now(timezone.utc) + timedelta(days=5))
                    - datetime(year=1970, month=1, day=1, tzinfo=timezone.utc)
                ).total_seconds()
            ),
            "data": {"cookies": cookies},
        }
        save_authentication_key(data, pin)
        # Close the browser
        self.ws_request("Browser.close")
        show_msg(
            f'Operations completed!\r\nThe "NFAuthentication.key" file has been saved in current folder.\r\nYour PIN protection is: {pin}',
            TextFormat.COL_BLUE,
        )

    def get_browser_debug_endpoint(self):
        start_time = time.time()
        while time.time() - start_time < 15:
            with contextlib.suppress(TimeoutError, URLError, ValueError):
                data = (
                    urlopen(f"http://{LOCALHOST_ADDRESS}:{DEBUG_PORT}/json", timeout=1)
                    .read()
                    .decode("utf-8")
                )
                if not data:
                    raise ValueError
                for item in json.loads(data):
                    if item["type"] == "page":
                        endpoint = item["webSocketDebuggerUrl"]
                        self._ws = websocket.create_connection(endpoint)
                        return

                msg = "Chrome session page not found"
                raise Warning(msg)

        msg = "Unable to connect with the browser"
        raise Warning(msg)

    def wait_user_logged(self):
        start_time = time.time()
        while time.time() - start_time < 300:  # 5 min
            time.sleep(1)
            history_data = self.ws_request("Page.getNavigationHistory")
            history_index = history_data["currentIndex"]
            # If the current page url is like "https://www.n*****x.com/browse" means that the user should have logged in successfully
            if "/browse" in history_data["entries"][history_index]["url"]:
                return True
        return False

    @property
    def msg_id(self):
        self._msg_id += 1
        return self._msg_id

    @msg_id.setter
    def msg_id(self, value):
        self._msg_id = value

    def ws_request(self, method, params=None):
        req_id = self.msg_id
        message = json.dumps({"id": req_id, "method": method, "params": params or {}})
        self._ws.send(message)
        start_time = time.time()
        while time.time() - start_time <= 10:
            message = self._ws.recv()
            parsed_message = json.loads(message)
            if "result" in parsed_message and parsed_message["id"] == req_id:
                return parsed_message["result"]

        msg = "No data received from browser"
        raise Warning(msg)

    def ws_wait_event(self, method):
        start_time = time.time()
        while time.time() - start_time <= 10:
            message = self._ws.recv()
            parsed_message = json.loads(message)
            if "method" in parsed_message and parsed_message["method"] == method:
                return parsed_message

        msg = "No event data received from browser"
        raise Warning(msg)


# Helper methods
class TextFormat:
    """Terminal color codes"""

    COL_BLUE = "\033[94m"
    COL_GREEN = "\033[92m"
    COL_LIGHT_YELLOW = "\033[93m"
    COL_LIGHT_RED = "\033[91m"
    COL_LIGHT_BLUE = "\033[94m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def open_browser(browser_temp_path):
    params = [
        "--incognito",
        f"--user-data-dir={browser_temp_path}",
        f"--remote-debugging-port={DEBUG_PORT}",
        "--remote-allow-origins=*",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    dev_null = open(os.devnull, "wb")
    try:
        browser_path = get_browser_path()
        show_msg(f"Browser startup... ({browser_path}) please wait")
        args = [browser_path, *params]
        return subprocess.Popen(args, stdout=dev_null, stderr=subprocess.STDOUT)
    finally:
        dev_null.close()


def get_browser_path():
    """Check and return the name of the installed browser."""
    if "*" not in BROWSER_PATH:
        return BROWSER_PATH
    if IS_MACOS:
        for browser_name in MACOS_BROWSERS:
            path = f"/Applications/{browser_name}.app/Contents/MacOS/{browser_name}"
            if Path(path).exists():
                return path
    else:
        for browser_name in LINUX_BROWSERS:
            with contextlib.suppress(subprocess.CalledProcessError):
                if path := (
                    subprocess.check_output(["which", browser_name])
                    .decode("utf-8")
                    .strip()
                ):
                    return path

    msg = 'Browser not detected.\r\nTry check if it is installed or specify the path in the BROWSER_PATH field inside "NFAuthenticationKey.py" file'
    raise Warning(msg)


def assert_cookies(cookies):
    if not cookies:
        msg = "Not found cookies"
        raise Warning(msg)
    login_cookies = ["nfvdid", "SecureNetflixId", "NetflixId"]
    for cookie_name in login_cookies:
        if all(cookie["name"] != cookie_name for cookie in cookies):
            raise Warning("Not found cookies")


def extract_json(content, var_name):
    try:
        pattern = r"netflix\.{}\s*=\s*(.*?);\s*</script>"
        json_array = re.findall(pattern.format(var_name), content, re.DOTALL)
        json_str = json_array[0]
        json_str_replace = json_str.replace(r"\"", r'\\"')  # Escape \"
        json_str_replace = json_str_replace.replace(r"\s", r"\\s")  # Escape whitespace
        json_str_replace = json_str_replace.replace(r"\r", r"\\r")  # Escape return
        json_str_replace = json_str_replace.replace(r"\n", r"\\n")  # Escape line feed
        json_str_replace = json_str_replace.replace(r"\t", r"\\t")  # Escape tab
        # Unicode property not supported, we change slash to avoid unescape it
        json_str_replace = json_str_replace.replace(r"\p", r"/p")
        # Decode the string as unicode
        json_str_replace = json_str_replace.encode().decode("unicode_escape")
        # Escape backslash (only when is not followed by double quotation marks \")
        json_str_replace = re.sub(r'\\(?!["])', r"\\\\", json_str_replace)
        return json.loads(json_str_replace)

    except Exception:
        return None


def save_authentication_key(data, pin):
    pin_str = (str(pin) + str(pin) + str(pin) + str(pin)).encode("utf-8")
    iv = "\x00" * 16
    cipher = AES.new(pin_str, AES.MODE_CBC, iv.encode("utf-8"))
    data_to_pad = json.dumps(data).encode("utf-8")
    raw = bytes(Padding.pad(data_to_pad=data_to_pad, block_size=16))
    encrypted_data = base64.b64encode(cipher.encrypt(raw)).decode("utf-8")

    with Path("NFAuthentication.key").open("w") as file:
        file.write(encrypted_data)


def show_msg(text, text_format=None):
    if text_format:
        text = text_format + text + TextFormat.END
    print(text)


def input_msg(text, text_format=None):
    if text_format:
        text = text_format + text + TextFormat.END
    return input(text)


if __name__ == "__main__":
    temp_path = tempfile.mkdtemp()
    try:
        Main(temp_path)
    except KeyboardInterrupt:
        show_msg("\r\nOperations cancelled")
    finally:
        with contextlib.suppress(Exception):
            shutil.rmtree(temp_path)
