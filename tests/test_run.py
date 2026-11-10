import contextlib
import io
import json
import sys
import unittest
from unittest.mock import patch

import run


class RunnerTest(unittest.TestCase):
    def invoke(self, arguments, suites, build_status=0):
        with (
            patch.object(
                sys, "argv", ["run.py", "--system", "fixture-system", *arguments]
            ),
            patch.object(run, "nix_output", return_value=json.dumps(suites)),
            patch.object(run.subprocess, "call", return_value=build_status) as build,
            contextlib.redirect_stdout(io.StringIO()) as output,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            try:
                status = run.main()
            except SystemExit as error:
                status = error.code
            return status, output.getvalue(), build.call_args

    def test_fast_suite_does_not_run_vm_tests(self):
        status, _, build = self.invoke([], {"fast": ["unit"], "e2e": ["vm"]})
        self.assertEqual(status, 0)
        self.assertEqual(
            build.args[0],
            [
                "nix",
                "build",
                "--no-link",
                "--print-build-logs",
                ".#checks.fixture-system.unit",
            ],
        )

    def test_new_suite_and_names_need_no_runner_changes(self):
        status, _, build = self.invoke(
            ["--suite", "integration", "new-test"],
            {"integration": ["new-test", "other"]},
        )
        self.assertEqual(status, 0)
        self.assertEqual(build.args[0][-1], ".#checks.fixture-system.new-test")

    def test_listing_does_not_build(self):
        status, output, build = self.invoke(
            ["--list", "--suite", "all"], {"fast": ["unit"], "e2e": ["vm"]}
        )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output), ["unit", "vm"])
        self.assertIsNone(build)

    def test_unknown_suite_or_test_does_not_build(self):
        for args in (["--suite", "missing"], ["missing"], ["vm"]):
            with self.subTest(args=args):
                status, _, build = self.invoke(args, {"fast": ["unit"], "e2e": ["vm"]})
                self.assertEqual(status, 2)
                self.assertIsNone(build)

    def test_empty_suite_can_be_listed_but_not_run(self):
        status, output, build = self.invoke(["--suite", "e2e", "--list"], {"e2e": []})
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output), [])
        self.assertIsNone(build)
        status, _, build = self.invoke(["--suite", "e2e"], {"e2e": []})
        self.assertEqual(status, 2)
        self.assertIsNone(build)

    def test_build_failure_is_propagated(self):
        status, _, _ = self.invoke([], {"fast": ["unit"]}, build_status=17)
        self.assertEqual(status, 17)


if __name__ == "__main__":
    unittest.main()
