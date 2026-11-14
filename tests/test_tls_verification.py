import sys
import unittest
from unittest.mock import Mock, patch

import vanguard
from scanner.crawler import Crawler
from scanner.headers import HeaderScanner
from scanner.vulnerabilities import VulnerabilityScanner


TARGET = "https://target.test"


class TLSVerificationTests(unittest.TestCase):
    def _option_cases(self):
        return (
            ("secure default", {}, True),
            ("explicit insecure opt-in", {"verify_tls": False}, False),
        )

    def test_crawler_verifies_certificates_by_default_and_supports_opt_in(self):
        for label, options, expected in self._option_cases():
            with self.subTest(option=label):
                with patch("scanner.crawler.requests.get", return_value=Mock(status_code=200, text="")) as get:
                    Crawler(TARGET, **options).get_links_and_forms(TARGET)
                self.assertIs(get.call_args.kwargs["verify"], expected)

    def test_header_scanner_verifies_certificates_by_default_and_supports_opt_in(self):
        for label, options, expected in self._option_cases():
            with self.subTest(option=label):
                with patch("scanner.headers.requests.get", return_value=Mock(headers={})) as get:
                    HeaderScanner(TARGET, **options).analyze()
                self.assertIs(get.call_args.kwargs["verify"], expected)

    def test_vulnerability_parameter_requests_verify_by_default_and_support_opt_in(self):
        for label, options, expected in self._option_cases():
            with self.subTest(option=label):
                with patch("scanner.vulnerabilities.requests.get", return_value=Mock(text="")) as get:
                    VulnerabilityScanner(**options).test_url_parameters(f"{TARGET}/search?q=1")
                self.assertGreater(get.call_count, 0)
                self.assertTrue(all(call.kwargs["verify"] is expected for call in get.call_args_list))

    def test_vulnerability_form_get_and_post_requests_verify_by_default_and_support_opt_in(self):
        form = {
            "url": TARGET,
            "action": f"{TARGET}/submit",
            "method": "get",
            "inputs": [{"name": "q", "type": "text"}],
        }
        for method in ("get", "post"):
            form["method"] = method
            for label, options, expected in self._option_cases():
                with self.subTest(method=method, option=label):
                    with patch("scanner.vulnerabilities.requests.get", return_value=Mock(text="")) as get, patch(
                        "scanner.vulnerabilities.requests.post", return_value=Mock(text="")
                    ) as post:
                        VulnerabilityScanner(**options).test_form(form)
                    request = post if method == "post" else get
                    self.assertGreater(request.call_count, 0)
                    self.assertTrue(all(call.kwargs["verify"] is expected for call in request.call_args_list))

    def test_cli_uses_secure_default_and_exposes_explicit_insecure_opt_in(self):
        for insecure, expected in ((False, True), (True, False)):
            with self.subTest(insecure=insecure):
                argv = ["vanguard.py", TARGET]
                if insecure:
                    argv.append("--insecure")

                header_scanner = Mock()
                header_scanner.analyze.return_value = []
                crawler = Mock()
                crawler.crawl.return_value = ([TARGET], [])
                vulnerability_scanner = Mock()
                vulnerability_scanner.test_url_parameters.return_value = []
                reporter = Mock()
                reporter.generate.return_value = "unused-report.html"

                with patch.object(sys, "argv", argv), patch.object(vanguard, "console"), patch.object(
                    vanguard, "Progress"
                ) as progress_class, patch.object(
                    vanguard, "HeaderScanner", return_value=header_scanner
                ) as header_class, patch.object(
                    vanguard, "Crawler", return_value=crawler
                ) as crawler_class, patch.object(
                    vanguard, "VulnerabilityScanner", return_value=vulnerability_scanner
                ) as vulnerability_class, patch.object(
                    vanguard, "ReportGenerator", return_value=reporter
                ):
                    progress_class.return_value.__enter__.return_value.add_task.return_value = 1
                    vanguard.main()

                header_class.assert_called_once_with(TARGET, verify_tls=expected)
                crawler_class.assert_called_once_with(TARGET, max_pages=15, verify_tls=expected)
                vulnerability_class.assert_called_once_with(verify_tls=expected)


if __name__ == "__main__":
    unittest.main()
