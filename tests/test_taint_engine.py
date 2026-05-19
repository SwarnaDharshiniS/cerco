"""Tests for analysis.taint.taint_engine."""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.taint import analyze_source, analyze_to_dict, TaintFinding


def findings(code: str) -> list[TaintFinding]:
    return analyze_source(textwrap.dedent(code))


def sinks(code: str) -> list[str]:
    return [f.sink_name for f in findings(code)]


def severities(code: str) -> list[str]:
    return [f.severity for f in findings(code)]


# ---------------------------------------------------------------------------
# No-finding cases (clean code)
# ---------------------------------------------------------------------------

class TestCleanCode(unittest.TestCase):

    def test_no_user_input(self):
        self.assertEqual(findings("os.system('ls')"), [])

    def test_constant_to_sink(self):
        self.assertEqual(findings("import os\nos.system('ls -l')"), [])

    def test_literal_eval(self):
        self.assertEqual(findings("eval('1+1')"), [])

    def test_sanitized_input_int(self):
        self.assertEqual(findings("""
            x = input('n: ')
            n = int(x)
            import os
            os.system('echo ' + str(n))
        """), [])

    def test_sanitized_shlex(self):
        self.assertEqual(findings("""
            import shlex, subprocess
            cmd = input()
            safe = shlex.quote(cmd)
            subprocess.run(safe, shell=True)
        """), [])

    def test_no_taint_through_compare(self):
        # comparison result is a bool, not injectable
        self.assertEqual(findings("""
            x = input()
            if x == 'admin':
                import os
                os.system('ls')
        """), [])


# ---------------------------------------------------------------------------
# Direct source → sink flows
# ---------------------------------------------------------------------------

class TestDirectFlows(unittest.TestCase):

    def test_input_to_eval(self):
        fs = findings("x = input(); eval(x)")
        self.assertTrue(any(f.sink_name == "eval" for f in fs))

    def test_input_to_exec(self):
        fs = findings("x = input(); exec(x)")
        self.assertTrue(any(f.sink_name == "exec" for f in fs))

    def test_input_to_os_system(self):
        fs = findings("""
            import os
            cmd = input('cmd: ')
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_sys_argv_to_os_system(self):
        fs = findings("""
            import sys, os
            os.system(sys.argv[1])
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_sys_argv_to_eval(self):
        fs = findings("""
            import sys
            eval(sys.argv[1])
        """)
        self.assertTrue(any(f.sink_name == "eval" for f in fs))

    def test_input_to_subprocess_run(self):
        fs = findings("""
            import subprocess
            cmd = input()
            subprocess.run(cmd, shell=True)
        """)
        self.assertTrue(any("subprocess" in f.sink_name for f in fs))

    def test_input_to_subprocess_popen(self):
        fs = findings("""
            import subprocess
            subprocess.Popen(input())
        """)
        self.assertTrue(any("subprocess" in f.sink_name for f in fs))

    def test_env_var_to_os_system(self):
        fs = findings("""
            import os
            cmd = os.environ.get('CMD')
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_getenv_to_eval(self):
        fs = findings("""
            import os
            code = os.getenv('SCRIPT')
            eval(code)
        """)
        self.assertTrue(any(f.sink_name == "eval" for f in fs))


# ---------------------------------------------------------------------------
# Indirect / multi-hop flows
# ---------------------------------------------------------------------------

class TestIndirectFlows(unittest.TestCase):

    def test_two_hop_assignment(self):
        fs = findings("""
            import os
            a = input()
            b = a
            os.system(b)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_string_concat(self):
        fs = findings("""
            import os
            user = input()
            cmd = 'echo ' + user
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_fstring_propagation(self):
        fs = findings("""
            import os
            name = input()
            cmd = f'hello {name}'
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_strip_does_not_sanitize(self):
        fs = findings("""
            import os
            cmd = input().strip()
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_aug_assign_propagation(self):
        fs = findings("""
            import os
            cmd = 'ls '
            cmd += input()
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_list_container_propagation(self):
        fs = findings("""
            import subprocess
            arg = input()
            args = ['cmd', arg]
            subprocess.run(args)
        """)
        self.assertTrue(any("subprocess" in f.sink_name for f in fs))

    def test_tuple_unpack_propagation(self):
        fs = findings("""
            import os
            a, b = sys_args = input().split()
            os.system(a)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_subscript_propagation(self):
        fs = findings("""
            import os, sys
            argv = sys.argv
            os.system(argv[1])
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_dict_value_propagation(self):
        fs = findings("""
            import os
            data = {'cmd': input()}
            os.system(data['cmd'])
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))


# ---------------------------------------------------------------------------
# Import alias handling
# ---------------------------------------------------------------------------

class TestImportAliases(unittest.TestCase):

    def test_from_sys_import_argv(self):
        fs = findings("""
            from sys import argv
            import os
            os.system(argv[1])
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_import_sys_as_alias(self):
        fs = findings("""
            import sys as s, os
            os.system(s.argv[1])
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_from_os_import_environ(self):
        fs = findings("""
            from os import environ
            eval(environ['CODE'])
        """)
        self.assertTrue(any(f.sink_name == "eval" for f in fs))


# ---------------------------------------------------------------------------
# Branch / conditional flows
# ---------------------------------------------------------------------------

class TestBranchFlows(unittest.TestCase):

    def test_taint_in_true_branch(self):
        fs = findings("""
            import os
            x = input()
            if x:
                os.system(x)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_taint_reassigned_in_branch(self):
        fs = findings("""
            import os
            x = input()
            if len(x) > 0:
                x = 'safe'
            os.system(x)
        """)
        # After merge, x may still be tainted from the path that skips the if
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_taint_in_else_branch(self):
        fs = findings("""
            import os
            flag = True
            if flag:
                cmd = 'ls'
            else:
                cmd = input()
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))


# ---------------------------------------------------------------------------
# Loop flows
# ---------------------------------------------------------------------------

class TestLoopFlows(unittest.TestCase):

    def test_for_loop_over_argv(self):
        fs = findings("""
            import os, sys
            for arg in sys.argv:
                os.system(arg)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_while_loop_with_input(self):
        fs = findings("""
            import os
            while True:
                cmd = input()
                os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_taint_accumulates_in_loop(self):
        fs = findings("""
            import os
            result = ''
            for part in input().split():
                result += part
            os.system(result)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))


# ---------------------------------------------------------------------------
# Function / interprocedural
# ---------------------------------------------------------------------------

class TestInterprocedural(unittest.TestCase):

    def test_tainted_arg_reaches_sink_in_callee(self):
        fs = findings("""
            import os
            def run(cmd):
                os.system(cmd)
            run(input())
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_tainted_through_return_value(self):
        fs = findings("""
            import os
            def get_cmd():
                return input()
            cmd = get_cmd()
            os.system(cmd)
        """)
        # Conservative: return value carries taint
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_clean_function_no_finding(self):
        fs = findings("""
            import os
            def run(cmd):
                os.system(cmd)
            run('ls')     # constant argument — clean
        """)
        self.assertEqual(fs, [])

    def test_keyword_arg_tainted(self):
        fs = findings("""
            import os
            def run(cmd='ls'):
                os.system(cmd)
            run(cmd=input())
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))


# ---------------------------------------------------------------------------
# Try / except flows
# ---------------------------------------------------------------------------

class TestTryFlows(unittest.TestCase):

    def test_taint_in_try_body(self):
        fs = findings("""
            import os
            try:
                cmd = input()
                os.system(cmd)
            except Exception:
                pass
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_taint_survives_try_except(self):
        fs = findings("""
            import os
            cmd = input()
            try:
                pass
            except Exception:
                pass
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class TestSeverity(unittest.TestCase):

    def test_eval_is_critical(self):
        fs = findings("eval(input())")
        critical = [f for f in fs if f.sink_name == "eval"]
        self.assertTrue(all(f.severity == "CRITICAL" for f in critical))

    def test_os_system_is_critical(self):
        fs = findings("import os; os.system(input())")
        cs = [f for f in fs if f.sink_name == "os.system"]
        self.assertTrue(all(f.severity == "CRITICAL" for f in cs))

    def test_open_is_medium(self):
        fs = findings("open(input())")
        opens = [f for f in fs if f.sink_name == "open"]
        self.assertTrue(all(f.severity == "MEDIUM" for f in opens))

    def test_requests_get_is_high(self):
        fs = findings("import requests; requests.get(input())")
        rg = [f for f in fs if f.sink_name == "requests.get"]
        self.assertTrue(all(f.severity == "HIGH" for f in rg))


# ---------------------------------------------------------------------------
# Taint path / chain
# ---------------------------------------------------------------------------

class TestTaintPath(unittest.TestCase):

    def test_path_has_source_step(self):
        fs = findings("eval(input())")
        self.assertTrue(fs)
        path = fs[0].tags[0].path_summary()
        self.assertEqual(path[0]["kind"], "source")
        self.assertIn("input", path[0]["expr"])

    def test_path_records_intermediate_assignment(self):
        fs = findings("""
            import os
            x = input()
            os.system(x)
        """)
        self.assertTrue(fs)
        path = fs[0].tags[0].path_summary()
        variables = [s.get("variable") for s in path]
        self.assertIn("x", variables)

    def test_multi_hop_path(self):
        fs = findings("""
            import os
            a = input()
            b = a
            c = b + '!'
            os.system(c)
        """)
        self.assertTrue(fs)
        path = fs[0].tags[0].path_summary()
        self.assertGreaterEqual(len(path), 3)

    def test_source_kind_input(self):
        fs = findings("eval(input())")
        self.assertEqual(fs[0].tags[0].source_kind, "input")

    def test_source_kind_sys_argv(self):
        fs = findings("import sys; eval(sys.argv[1])")
        self.assertEqual(fs[0].tags[0].source_kind, "sys_argv")

    def test_source_kind_env_var(self):
        fs = findings("import os; eval(os.environ.get('X'))")
        self.assertEqual(fs[0].tags[0].source_kind, "env_var")


# ---------------------------------------------------------------------------
# Output serialisation
# ---------------------------------------------------------------------------

class TestSerialisation(unittest.TestCase):

    def test_finding_to_dict(self):
        fs = findings("eval(input())")
        d = fs[0].to_dict()
        self.assertIn("severity", d)
        self.assertIn("sink", d)
        self.assertIn("sources", d)
        self.assertIn("taint_paths", d)
        self.assertIn("message", d)
        self.assertIn("location", d)

    def test_analyze_to_dict_structure(self):
        import json
        report = analyze_to_dict("import os; os.system(input())")
        self.assertIn("total", report)
        self.assertIn("critical", report)
        self.assertIn("findings", report)
        # must be JSON-serialisable
        json.dumps(report)

    def test_finding_str(self):
        fs = findings("eval(input())")
        self.assertIn("eval", str(fs[0]))

    def test_empty_report(self):
        report = analyze_to_dict("x = 1")
        self.assertEqual(report["total"], 0)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_empty_source(self):
        self.assertEqual(findings(""), [])

    def test_chained_string_methods(self):
        fs = findings("""
            import os
            cmd = input().strip().lower()
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_list_comprehension_taint(self):
        fs = findings("""
            import subprocess
            args = [x for x in input().split()]
            subprocess.run(args)
        """)
        self.assertTrue(any("subprocess" in f.sink_name for f in fs))

    def test_multiple_sinks(self):
        fs = findings("""
            import os, subprocess
            cmd = input()
            os.system(cmd)
            subprocess.run(cmd)
            eval(cmd)
        """)
        sink_names = {f.sink_name for f in fs}
        self.assertIn("os.system", sink_names)
        self.assertIn("eval", sink_names)

    def test_multiple_sources(self):
        fs = findings("""
            import os, sys
            cmd = input() + sys.argv[1]
            os.system(cmd)
        """)
        source_kinds = {t.source_kind for f in fs for t in f.tags}
        self.assertIn("input", source_kinds)
        self.assertIn("sys_argv", source_kinds)

    def test_format_string_propagation(self):
        fs = findings("""
            import os
            user = input()
            cmd = 'echo {}'.format(user)
            os.system(cmd)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_stdin_read_source(self):
        fs = findings("""
            import sys, os
            data = sys.stdin.read()
            os.system(data)
        """)
        self.assertTrue(any(f.sink_name == "os.system" for f in fs))

    def test_os_environ_direct(self):
        fs = findings("""
            import os
            env = os.environ
            eval(env['CODE'])
        """)
        self.assertTrue(any(f.sink_name == "eval" for f in fs))


if __name__ == "__main__":
    unittest.main()
