"""
Test suite for simple python port scanner
"""

import io, sys, unittest
from port_scanner import PortScanner, ConcurrencyEngine

class TestPortScanner(unittest.TestCase):

    def test_successfull_port_test_returns_true(self):
        result = PortScanner(ConcurrencyEngine).test_port("python.org", 80)
        self.assertEqual(result, True)

    def test_unsuccessfull_port_test_returns_false(self):
        result = PortScanner(ConcurrencyEngine).test_port("scanme.nmap.org", 12)
        self.assertEqual(result, False)

    def test_successfull_run_scan_returns_results_message(self):
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        PortScanner(ConcurrencyEngine).run_scan("python.org", 26)
        sys.stdout = sys.__stdout__
        self.assertEqual(capturedOutput.getvalue(), "python.org:25 open\n")

    def test_unsuccessfull_run_scan_returns_empty_message(self):
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        PortScanner(ConcurrencyEngine).run_scan("scanme.nmap.org", 12)
        sys.stdout = sys.__stdout__
        self.assertEqual(capturedOutput.getvalue(), '')
