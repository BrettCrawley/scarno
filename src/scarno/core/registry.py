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

"""Language analyser registry — REQ-9.

Each language analyser registers itself at module-import time:

.. code-block:: python

    # src/scarno/analysers/python/__init__.py
    from scarno.core.registry import register
    ...
    register("python", PythonAnalyser)

The CLI orchestrator then looks up analysers by the language keys
returned from :func:`scarno.core.detector.detect_project_types`,
removing the hard-coded dispatch that used to live in ``cli.py``.

Registration is idempotent: re-registering the same ``(language, cls)``
pair is a no-op; registering a *different* class for a language already
present replaces the previous entry (the last import wins).
"""
from __future__ import annotations

from scarno.core.base_analyser import BaseAnalyser

_REGISTRY: dict[str, type[BaseAnalyser]] = {}


def register(language: str, cls: type[BaseAnalyser]) -> None:
    """Register an analyser class for a language key."""
    _REGISTRY[language] = cls


def get_analyser(language: str) -> BaseAnalyser | None:
    """Return a fresh analyser instance for a language, or ``None``."""
    cls = _REGISTRY.get(language)
    if cls is None:
        return None
    return cls()


def analysers_for(languages: list[str]) -> list[BaseAnalyser]:
    """Return analyser instances for every known language in ``languages``."""
    out: list[BaseAnalyser] = []
    for lang in languages:
        analyser = get_analyser(lang)
        if analyser is not None:
            out.append(analyser)
    return out


def registered_languages() -> list[str]:
    """Return the sorted list of registered language keys."""
    return sorted(_REGISTRY.keys())


def clear() -> None:
    """Remove every registration. Test-only — never call from production."""
    _REGISTRY.clear()
