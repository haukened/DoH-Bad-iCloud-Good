import unittest
from generate import DNSResults, DNSResult, log, now, read_domains
from unittest.mock import patch

class TestDNSResult(unittest.TestCase):
    def test_init(self):
        result = DNSResult('192.0.2.0', {'example.com', 'test.com'})
        self.assertEqual(result.addr, '192.0.2.0')
        self.assertEqual(result.domains, ['example.com', 'test.com'])

    def test_sorted_domains(self):
        result = DNSResult('192.0.2.0', {'test.com', 'example.com'})
        self.assertEqual(result.domains, ['example.com', 'test.com'])

class TestDNSResults(unittest.TestCase):
    def test_init(self):
        results = DNSResults()
        self.assertEqual(len(results), 0)
        self.assertEqual(results.num_resolved, 0)
        self.assertEqual(results.num_failed, 0)
        self.assertEqual(results.domains_passed, [])
        self.assertEqual(results.domains_failed, [])
        self.assertEqual(results.IPv4Addrs, [])
        self.assertEqual(results.IPv6Addrs, [])

    def test_add(self):
        results = DNSResults()
        # Add two domains that resolve to the same address
        # but make sure they are non-alphabetical
        results.add('test.com', '1.1.1.1')
        results.passed('test.com')
        results.add('example.com', '1.1.1.1')
        results.passed('example.com')
        # these are local address and shouldn't actually add
        results.add('example.com', '2001:db8::1')
        results.add('nowhere.lan', '192.168.0.2')
        results.add('foo.local', 'fe80::1')
        # now test that we only have one routeable IP address
        self.assertEqual(len(results), 1)
        # but that we had two domains resolve to it
        self.assertEqual(results.num_resolved, 2)
        # and no domains failed
        self.assertEqual(results.num_failed, 0)
        # and that the domains are sorted
        self.assertEqual(results.domains_passed, ['example.com', 'test.com'])
        # and that the failed domains are empty
        self.assertEqual(results.domains_failed, [])
        # and that we have one address
        self.assertEqual(len(results.IPv4Addrs), 1)
        # validate that two domains map to the same address
        self.assertEqual(results.IPv4Addrs[0].addr, '1.1.1.1')
        self.assertEqual(results.IPv4Addrs[0].domains, ['example.com', 'test.com'])
        # and that we have no IPv6 addresses
        self.assertEqual(len(results.IPv6Addrs), 0)

    def test_failed(self):
        results = DNSResults()
        results.failed('example.com')
        results.failed('test.com')
        self.assertEqual(len(results), 0)
        self.assertEqual(results.num_resolved, 0)
        self.assertEqual(results.num_failed, 2)
        self.assertEqual(results.domains_passed, [])
        self.assertEqual(results.domains_failed, ['example.com', 'test.com'])
        self.assertEqual(results.IPv4Addrs, [])
        self.assertEqual(results.IPv6Addrs, [])

    def test_passed(self):
        results = DNSResults()
        results.passed('example.com')
        results.passed('test.com')
        self.assertEqual(len(results), 0)
        self.assertEqual(results.num_resolved, 2)
        self.assertEqual(results.num_failed, 0)
        self.assertEqual(results.domains_passed, ['example.com', 'test.com'])
        self.assertEqual(results.domains_failed, [])
        self.assertEqual(results.IPv4Addrs, [])
        self.assertEqual(results.IPv6Addrs, [])
    
class TestLog(unittest.TestCase):
    @patch('builtins.print')
    def test_log(self, mock_print):
        log("This is a log message")
        mock_print.assert_called_once_with("::: This is a log message")

class TestNow(unittest.TestCase):
    def test_now(self):
        result = now()
        self.assertIsInstance(result, str)
        self.assertRegex(result, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

if __name__ == '__main__':
    unittest.main()