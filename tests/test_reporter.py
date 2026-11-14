from html.parser import HTMLParser
import os
import tempfile
import unittest

from scanner.reporter import ReportGenerator


class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.event_attributes = []

    def handle_starttag(self, tag, attrs):
        self._record(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._record(tag, attrs)

    def _record(self, tag, attrs):
        self.tags.append(tag)
        self.event_attributes.extend(
            (name.lower(), value)
            for name, value in attrs
            if name.lower().startswith("on")
        )


class ReportHTMLInjectionTests(unittest.TestCase):
    def test_dynamic_scan_fields_are_escaped(self):
        target = 'https://target.test/"><script id="target-injection">alert(0)</script>'
        finding = {
            "severity": 'Low" onclick="alert(1)',
            "type": '"><img src=x onerror=alert(2)>',
            "name": "<svg onload=alert(3)>",
            "description": "</p><iframe src=x></iframe>",
            "impact": "<script>alert(4)</script>",
            "remediation": "<object data=x></object>",
            "url": 'https://target.test/?q="><img src=x onerror=alert(5)>',
            "parameter": 'x"><svg onload=alert(6)>',
            "method": 'GET" onmouseover="alert(7)',
            "payload": '<script>alert(8)</script> & "',
        }

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.html")
            report_path = ReportGenerator(target, [finding], 1, 1).generate(path)
            with open(report_path, encoding="utf-8") as report_file:
                report = report_file.read()

        self.assertIn('&lt;script id=&quot;target-injection&quot;&gt;', report)
        self.assertNotIn('<script id="target-injection">', report)

        parser = _TagCollector()
        parser.feed(report)
        self.assertEqual(parser.tags.count("script"), 1)
        for injected_tag in ("img", "svg", "iframe", "object"):
            self.assertNotIn(injected_tag, parser.tags)
        self.assertEqual(parser.event_attributes, [("onclick", "toggleFinding('finding-0')")])


if __name__ == "__main__":
    unittest.main()
