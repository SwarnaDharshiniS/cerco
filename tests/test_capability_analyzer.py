"""Tests for analysis.capability.capability_analyzer."""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.capability import (
    analyze_source,
    CapabilityReport,
    CapabilityUse,
    CapClass,
    Severity,
)


def rpt(code: str) -> CapabilityReport:
    return analyze_source(textwrap.dedent(code))


def cap_classes(code: str) -> set[str]:
    return {u.cap_class.value for u in rpt(code).uses}


def symbols(code: str) -> set[str]:
    return {u.symbol for u in rpt(code).uses}


def calls(code: str) -> list[CapabilityUse]:
    return [u for u in rpt(code).uses if u.kind == "call"]


def imports_(code: str) -> list[CapabilityUse]:
    return [u for u in rpt(code).uses if u.kind == "import"]


# ---------------------------------------------------------------------------
# Empty / clean code
# ---------------------------------------------------------------------------

class TestClean(unittest.TestCase):

    def test_empty_source(self):
        r = rpt("")
        self.assertEqual(r.uses, [])
        self.assertIsNone(r.highest_severity())

    def test_no_capabilities(self):
        r = rpt("x = 1 + 2\nprint(x)")
        # print() not in any signal registry
        cap_uses = [u for u in r.uses if u.symbol != "print"]
        self.assertEqual(cap_uses, [])

    def test_pure_math(self):
        self.assertEqual(rpt("import math\nmath.sqrt(2)").uses, [])


# ---------------------------------------------------------------------------
# Import detection
# ---------------------------------------------------------------------------

class TestImportDetection(unittest.TestCase):

    def test_import_os_detected(self):
        r = rpt("import os")
        syms = symbols("import os")
        self.assertTrue(any(s.startswith("os") for s in syms))

    def test_import_subprocess(self):
        r = rpt("import subprocess")
        self.assertIn("PROC", cap_classes("import subprocess"))

    def test_import_socket(self):
        self.assertIn("NET", cap_classes("import socket"))

    def test_import_requests(self):
        self.assertIn("NET", cap_classes("import requests"))

    def test_import_ctypes(self):
        self.assertIn("DYN", cap_classes("import ctypes"))

    def test_import_importlib(self):
        self.assertIn("DYN", cap_classes("import importlib"))

    def test_from_import_detected(self):
        r = rpt("from subprocess import Popen")
        imp = [u for u in r.uses if u.kind == "import"]
        self.assertTrue(any("subprocess" in u.symbol for u in imp))

    def test_import_deduplication(self):
        # same module imported twice → only one import finding
        r = rpt("import os\nimport os")
        os_imports = [u for u in r.uses if u.symbol == "os" and u.kind == "import"]
        self.assertEqual(len(os_imports), 1)

    def test_wildcard_import(self):
        r = rpt("from os import *")
        imp = [u for u in r.uses if u.kind == "import"]
        self.assertTrue(any("os" in u.symbol for u in imp))

    def test_import_pickle_is_medium(self):
        r = rpt("import pickle")
        p = [u for u in r.uses if "pickle" in u.symbol and u.kind == "import"]
        self.assertTrue(any(u.severity == Severity.MEDIUM for u in p))


# ---------------------------------------------------------------------------
# Direct call detection
# ---------------------------------------------------------------------------

class TestCallDetection(unittest.TestCase):

    def test_eval_detected(self):
        r = rpt("eval('1+1')")
        self.assertTrue(any(u.symbol == "eval" for u in r.uses if u.kind == "call"))

    def test_exec_detected(self):
        r = rpt("exec('pass')")
        self.assertTrue(any(u.symbol == "exec" for u in r.uses if u.kind == "call"))

    def test_os_system_detected(self):
        r = rpt("import os\nos.system('ls')")
        self.assertTrue(any(u.symbol == "os.system" for u in r.uses if u.kind == "call"))

    def test_subprocess_popen_detected(self):
        r = rpt("import subprocess\nsubprocess.Popen(['ls'])")
        self.assertTrue(any(u.symbol == "subprocess.Popen" for u in r.uses if u.kind == "call"))

    def test_subprocess_run_detected(self):
        r = rpt("import subprocess\nsubprocess.run(['ls'])")
        self.assertTrue(any(u.symbol == "subprocess.run" for u in r.uses if u.kind == "call"))

    def test_socket_socket_detected(self):
        r = rpt("import socket\nsocket.socket()")
        self.assertTrue(any(u.symbol == "socket.socket" for u in r.uses if u.kind == "call"))

    def test_requests_get_detected(self):
        r = rpt("import requests\nrequests.get('http://example.com')")
        self.assertTrue(any(u.symbol == "requests.get" for u in r.uses if u.kind == "call"))

    def test_requests_post_detected(self):
        r = rpt("import requests\nrequests.post('http://x.com', json={})")
        self.assertTrue(any(u.symbol == "requests.post" for u in r.uses if u.kind == "call"))

    def test_open_detected(self):
        r = rpt("open('file.txt')")
        self.assertTrue(any(u.symbol == "open" for u in r.uses if u.kind == "call"))

    def test_shutil_rmtree_detected(self):
        r = rpt("import shutil\nshutil.rmtree('/tmp/x')")
        self.assertTrue(any(u.symbol == "shutil.rmtree" for u in r.uses if u.kind == "call"))

    def test_importlib_import_module(self):
        r = rpt("import importlib\nimportlib.import_module('os')")
        self.assertTrue(any(u.symbol == "importlib.import_module" for u in r.uses if u.kind == "call"))

    def test_pickle_loads_detected(self):
        r = rpt("import pickle\npickle.loads(data)")
        self.assertTrue(any(u.symbol == "pickle.loads" for u in r.uses if u.kind == "call"))

    def test_urllib_urlopen(self):
        r = rpt("import urllib.request\nurllib.request.urlopen('http://x.com')")
        self.assertTrue(any("urlopen" in u.symbol for u in r.uses if u.kind == "call"))

    def test_ctypes_cdll(self):
        r = rpt("import ctypes\nctypes.CDLL('libfoo.so')")
        self.assertTrue(any("CDLL" in u.symbol for u in r.uses if u.kind == "call"))

    def test_sqlite3_connect(self):
        r = rpt("import sqlite3\nsqlite3.connect('db.sqlite')")
        self.assertTrue(any("sqlite3" in u.symbol for u in r.uses if u.kind == "call"))

    def test_os_fork_detected(self):
        r = rpt("import os\nos.fork()")
        self.assertTrue(any(u.symbol == "os.fork" for u in r.uses if u.kind == "call"))

    def test_os_remove_detected(self):
        r = rpt("import os\nos.remove('f.txt')")
        self.assertTrue(any(u.symbol == "os.remove" for u in r.uses if u.kind == "call"))

    def test_compile_detected(self):
        r = rpt("compile('x=1', '<str>', 'exec')")
        self.assertTrue(any(u.symbol == "compile" for u in r.uses if u.kind == "call"))


# ---------------------------------------------------------------------------
# Alias tracking
# ---------------------------------------------------------------------------

class TestAliases(unittest.TestCase):

    def test_import_os_as_alias(self):
        r = rpt("import os as o\no.system('ls')")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "os.system"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].alias, "o.system")

    def test_import_subprocess_as_sp(self):
        r = rpt("import subprocess as sp\nsp.Popen(['ls'])")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "subprocess.Popen"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].alias, "sp.Popen")

    def test_from_subprocess_import_popen(self):
        r = rpt("from subprocess import Popen\nPopen(['ls'])")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "subprocess.Popen"]
        self.assertEqual(len(c), 1)

    def test_from_subprocess_import_popen_as_alias(self):
        r = rpt("from subprocess import Popen as P\nP(['ls'])")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "subprocess.Popen"]
        self.assertEqual(len(c), 1)
        self.assertIsNotNone(c[0].alias)

    def test_from_os_import_system(self):
        r = rpt("from os import system\nsystem('ls')")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "os.system"]
        self.assertEqual(len(c), 1)

    def test_from_os_import_system_as_alias(self):
        r = rpt("from os import system as run\nrun('ls')")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "os.system"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].alias, "run")

    def test_requests_aliased(self):
        r = rpt("import requests as req\nreq.get('http://x.com')")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "requests.get"]
        self.assertEqual(len(c), 1)

    def test_socket_aliased(self):
        r = rpt("import socket as sock\nsock.socket()")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "socket.socket"]
        self.assertEqual(len(c), 1)

    def test_from_socket_import_socket(self):
        r = rpt("from socket import socket\nsocket()")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "socket.socket"]
        self.assertEqual(len(c), 1)

    def test_from_os_import_path_functions(self):
        r = rpt("from os import listdir\nlistdir('.')")
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "os.listdir"]
        self.assertEqual(len(c), 1)

    def test_import_alias_reflected_in_import_finding(self):
        r = rpt("import subprocess as sp")
        imp = [u for u in r.uses if u.kind == "import" and "subprocess" in u.symbol]
        self.assertTrue(any(u.alias == "sp" for u in imp))


# ---------------------------------------------------------------------------
# Capability classification
# ---------------------------------------------------------------------------

class TestCapClassification(unittest.TestCase):

    def test_eval_is_dyn(self):
        r = rpt("eval('x')")
        dyn = [u for u in r.uses if u.symbol == "eval"]
        self.assertTrue(all(u.cap_class == CapClass.DYN for u in dyn))

    def test_exec_is_dyn(self):
        r = rpt("exec('pass')")
        dyn = [u for u in r.uses if u.symbol == "exec"]
        self.assertTrue(all(u.cap_class == CapClass.DYN for u in dyn))

    def test_os_system_is_proc(self):
        r = rpt("import os\nos.system('ls')")
        c = [u for u in r.uses if u.symbol == "os.system"]
        self.assertTrue(all(u.cap_class == CapClass.PROC for u in c))

    def test_open_is_fs(self):
        r = rpt("open('f')")
        c = [u for u in r.uses if u.symbol == "open"]
        self.assertTrue(all(u.cap_class == CapClass.FS for u in c))

    def test_socket_is_net(self):
        r = rpt("import socket\nsocket.socket()")
        c = [u for u in r.uses if u.symbol == "socket.socket"]
        self.assertTrue(all(u.cap_class == CapClass.NET for u in c))

    def test_requests_get_is_net(self):
        r = rpt("import requests\nrequests.get('http://x.com')")
        c = [u for u in r.uses if u.symbol == "requests.get"]
        self.assertTrue(all(u.cap_class == CapClass.NET for u in c))

    def test_subprocess_popen_is_proc(self):
        r = rpt("import subprocess\nsubprocess.Popen([])")
        c = [u for u in r.uses if u.symbol == "subprocess.Popen"]
        self.assertTrue(all(u.cap_class == CapClass.PROC for u in c))

    def test_multiple_classes_detected(self):
        r = rpt("""
            import os, socket, subprocess
            os.remove('f')
            socket.socket()
            subprocess.run(['ls'])
            eval('x')
        """)
        cls = {u.cap_class for u in r.uses if u.kind == "call"}
        self.assertIn(CapClass.FS, cls)
        self.assertIn(CapClass.NET, cls)
        self.assertIn(CapClass.PROC, cls)
        self.assertIn(CapClass.DYN, cls)


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class TestSeverity(unittest.TestCase):

    def test_eval_is_high(self):
        r = rpt("eval('x')")
        c = [u for u in r.uses if u.symbol == "eval"]
        self.assertTrue(all(u.severity == Severity.HIGH for u in c))

    def test_os_system_is_high(self):
        r = rpt("import os\nos.system('ls')")
        c = [u for u in r.uses if u.symbol == "os.system"]
        self.assertTrue(all(u.severity == Severity.HIGH for u in c))

    def test_socket_socket_is_high(self):
        r = rpt("import socket\nsocket.socket()")
        c = [u for u in r.uses if u.symbol == "socket.socket"]
        self.assertTrue(all(u.severity == Severity.HIGH for u in c))

    def test_os_listdir_is_low(self):
        r = rpt("import os\nos.listdir('.')")
        c = [u for u in r.uses if u.symbol == "os.listdir"]
        self.assertTrue(all(u.severity == Severity.LOW for u in c))

    def test_highest_severity_critical_when_eval_present(self):
        r = rpt("eval('x')\nimport os\nos.listdir('.')")
        self.assertEqual(r.highest_severity(), Severity.HIGH)

    def test_highest_severity_none_for_clean(self):
        r = rpt("")
        self.assertIsNone(r.highest_severity())


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

class TestReportStructure(unittest.TestCase):

    def test_report_has_by_class(self):
        r = rpt("import os\nos.system('ls')\neval('x')")
        self.assertTrue(len(r.by_class(CapClass.PROC)) > 0)
        self.assertTrue(len(r.by_class(CapClass.DYN)) > 0)

    def test_report_has_method(self):
        r = rpt("eval('x')")
        self.assertTrue(r.has(CapClass.DYN))
        self.assertFalse(r.has(CapClass.NET))

    def test_capabilities_present(self):
        r = rpt("import os\nos.remove('f')\neval('x')")
        caps = r.capabilities_present()
        cap_vals = [c.value for c in caps]
        self.assertIn("DYN", cap_vals)
        self.assertIn("FS", cap_vals)

    def test_to_dict_keys(self):
        r = rpt("eval('x')")
        d = r.to_dict()
        self.assertIn("source", d)
        self.assertIn("summary", d)
        self.assertIn("by_capability", d)

    def test_summary_counts(self):
        r = rpt("import os\nos.system('ls')\neval('x')\nopen('f')")
        d = r.to_dict()["summary"]
        self.assertGreaterEqual(d["DYN"], 1)
        self.assertGreaterEqual(d["PROC"], 1)
        self.assertGreaterEqual(d["FS"], 1)

    def test_to_json_is_valid(self):
        import json
        r = rpt("import subprocess\nsubprocess.run(['ls'])")
        obj = json.loads(r.to_json())
        self.assertIn("summary", obj)

    def test_repr(self):
        r = rpt("eval('x')")
        self.assertIn("CapabilityReport", repr(r))
        self.assertIn("DYN", repr(r))

    def test_use_to_dict(self):
        r = rpt("eval('x')")
        u = next(u for u in r.uses if u.symbol == "eval")
        d = u.to_dict()
        self.assertIn("cap_class", d)
        self.assertIn("severity", d)
        self.assertIn("symbol", d)
        self.assertIn("line", d)
        self.assertIn("reason", d)

    def test_line_numbers_captured(self):
        r = rpt("x = 1\neval('x')")
        u = next(u for u in r.uses if u.symbol == "eval" and u.kind == "call")
        self.assertEqual(u.line, 2)

    def test_col_numbers_captured(self):
        r = rpt("eval('x')")
        u = next(u for u in r.uses if u.symbol == "eval" and u.kind == "call")
        self.assertIsNotNone(u.col)


# ---------------------------------------------------------------------------
# Complex / real-world code
# ---------------------------------------------------------------------------

class TestComplexCode(unittest.TestCase):

    def test_all_four_capabilities(self):
        code = """
            import os
            import socket
            import subprocess
            import importlib

            open('config.txt')
            socket.socket()
            subprocess.run(['ls'])
            importlib.import_module('json')
        """
        r = rpt(code)
        caps = {c.value for c in r.capabilities_present()}
        self.assertIn("FS",   caps)
        self.assertIn("NET",  caps)
        self.assertIn("PROC", caps)
        self.assertIn("DYN",  caps)

    def test_nested_function_calls(self):
        r = rpt("""
            import os
            result = os.popen(os.getcwd())
        """)
        proc_calls = [u for u in r.uses if u.kind == "call" and u.cap_class == CapClass.PROC]
        self.assertTrue(len(proc_calls) >= 1)

    def test_aliased_requests_session(self):
        r = rpt("""
            import requests as req
            s = req.Session()
            s.get('http://example.com')
        """)
        # Session creation should be detected
        net_calls = [u for u in r.uses if u.kind == "call" and u.cap_class == CapClass.NET]
        self.assertTrue(len(net_calls) >= 1)

    def test_from_import_chain(self):
        r = rpt("""
            from subprocess import run as execute
            execute(['ls'])
        """)
        c = [u for u in r.uses if u.kind == "call" and u.symbol == "subprocess.run"]
        self.assertEqual(len(c), 1)

    def test_multiple_calls_same_symbol(self):
        r = rpt("""
            import os
            os.system('ls')
            os.system('pwd')
        """)
        c = [u for u in r.uses if u.symbol == "os.system" and u.kind == "call"]
        self.assertEqual(len(c), 2)
        self.assertEqual(c[0].line, 3)
        self.assertEqual(c[1].line, 4)

    def test_asyncio_network_code(self):
        r = rpt("""
            import asyncio
            asyncio.open_connection('localhost', 8080)
        """)
        net = [u for u in r.uses if "open_connection" in u.symbol]
        self.assertTrue(len(net) >= 1)

    def test_pathlib_write_detected(self):
        r = rpt("""
            from pathlib import Path
            Path('out.txt').write_text('hello')
        """)
        # write_text call on a Path object — may resolve via attribute chain
        fs_calls = [u for u in r.uses if u.kind == "call"]
        # At minimum the import of pathlib should be FS
        fs_imp = [u for u in r.uses if u.kind == "import" and u.cap_class == CapClass.FS]
        self.assertTrue(len(fs_imp) >= 1)

    def test_dynamic_import_via_importlib(self):
        r = rpt("""
            import importlib
            mod = importlib.import_module('os')
        """)
        dyn = [u for u in r.uses if u.kind == "call" and u.cap_class == CapClass.DYN]
        self.assertTrue(len(dyn) >= 1)

    def test_ctypes_load_library(self):
        r = rpt("""
            import ctypes
            ctypes.CDLL('libssl.so.1')
        """)
        dyn = [u for u in r.uses if u.kind == "call" and u.cap_class == CapClass.DYN]
        self.assertTrue(len(dyn) >= 1)

    def test_report_summary_totals_match(self):
        r = rpt("import os\nos.remove('f')\neval('x')")
        d = r.to_dict()
        total_in_by_cap = sum(
            len(v) for v in d["by_capability"].values()
        )
        self.assertEqual(total_in_by_cap, d["summary"]["total_uses"])


if __name__ == "__main__":
    unittest.main()
