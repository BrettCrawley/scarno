"""Root conftest — registers the SRTM coverage plugin for every pytest run."""
from __future__ import annotations

pytest_plugins = ["tests.srtm_plugin"]
