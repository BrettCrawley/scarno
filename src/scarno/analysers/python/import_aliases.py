# Copyright 2026 Brett Crawley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Import-name → PyPI-name alias table.

Many popular PyPI packages are distributed under one name but imported
under a different one. ``pip install pillow`` gives you ``import PIL``;
``pip install opencv-python`` gives you ``import cv2``. Without a
translation table, source analysis would mis-classify these packages
as unused.

This table serves as a **fallback** for when the target packages are not
installed in the analysis environment. When packages *are* installed,
``importlib.metadata.packages_distributions()`` (inverted) provides the
mapping automatically. This table covers the common cases where the
target project's deps aren't in scarno's own venv.
"""
from __future__ import annotations

# Import name (lowercase) ↦ PyPI distribution name (PEP 503 canonical form).
IMPORT_ALIASES: dict[str, str] = {
    # ── Imaging / media ────────────────────────────────────────────────
    "pil": "pillow",
    "cv2": "opencv-python",
    "skimage": "scikit-image",
    # ── Data science / ML ──────────────────────────────────────────────
    "sklearn": "scikit-learn",
    "mx": "mxnet",
    "tf": "tensorflow",
    "attr": "attrs",
    "attrs": "attrs",
    # ── Web / HTTP ─────────────────────────────────────────────────────
    "bs4": "beautifulsoup4",
    "websocket": "websocket-client",
    "jose": "python-jose",
    "jwt": "pyjwt",
    "multipart": "python-multipart",
    # ── Serialisation / parsing ────────────────────────────────────────
    "yaml": "pyyaml",
    "lxml": "lxml",
    "msgpack": "msgpack",
    "ujson": "ujson",
    "toml": "toml",
    # ── Date / time ────────────────────────────────────────────────────
    "dateutil": "python-dateutil",
    # ── Environment / config ───────────────────────────────────────────
    "dotenv": "python-dotenv",
    "decouple": "python-decouple",
    # ── System / platform ──────────────────────────────────────────────
    "gi": "pygobject",
    "pkg_resources": "setuptools",
    "distutils": "setuptools",
    # ── Security / crypto ──────────────────────────────────────────────
    "openssl": "pyopenssl",
    "crypto": "pycryptodome",
    "cryptodome": "pycryptodome",
    "nacl": "pynacl",
    "ldap": "python-ldap",
    "tlsh": "py-tlsh",
    "fido2": "python-fido2",
    # ── Database ───────────────────────────────────────────────────────
    "psycopg2": "psycopg2-binary",
    "pymysql": "pymysql",
    "bson": "pymongo",
    "redis": "redis",
    "MySQLdb": "mysqlclient",
    "mysqldb": "mysqlclient",
    # ── Cloud / services ───────────────────────────────────────────────
    "google": "google-cloud-core",
    "boto": "boto3",
    # ── Async / networking ─────────────────────────────────────────────
    "dns": "dnspython",
    "socks": "pysocks",
    "paramiko": "paramiko",
    "serial": "pyserial",
    "usb": "pyusb",
    # ── CLI / terminal ─────────────────────────────────────────────────
    "click": "click",
    "rich": "rich",
    # ── Misc well-known mismatches ─────────────────────────────────────
    "magic": "python-magic",
    "levenshtein": "python-levenshtein",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "slugify": "python-slugify",
    "whois": "python-whois",
    "u2flib-server": "python-u2flib-server",
    "nvd3": "python-nvd3",
    "memcache": "python-memcached",
    "snap7": "python-snap7",
    "daemon": "python-daemon",
    "xlib": "python-xlib",
    "engineio": "python-engineio",
    "socketio": "python-socketio",
    "gitlab": "python-gitlab",
    "jenkins": "python-jenkins",
    "jsonschema": "jsonschema",
    "wcwidth": "wcwidth",
    "six": "six",
    "soupsieve": "soupsieve",
    "idna": "idna",
    "certifi": "certifi",
    "charset_normalizer": "charset-normalizer",
    "urllib3": "urllib3",
}
