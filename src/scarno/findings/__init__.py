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

"""Security-finding rule engine for Scarno (REQ-3c)."""
from __future__ import annotations

from scarno.findings.config import SuppressionConfig, load_suppression_config
from scarno.findings.engine import (
    apply_rules,
    scan_notebook_magics,
    scan_shell_script_for_curl_pipe,
)
from scarno.findings.rules import RULES, Rule

__all__ = [
    "RULES",
    "Rule",
    "SuppressionConfig",
    "apply_rules",
    "load_suppression_config",
    "scan_notebook_magics",
    "scan_shell_script_for_curl_pipe",
]
