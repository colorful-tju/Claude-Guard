"""Unprivileged YAML preview: counts only, no network and no configuration writes."""
import json
import pathlib
import subprocess
import unittest


class ProfileSummaryTests(unittest.TestCase):
    def summaries(self, values):
        result = subprocess.run(['/usr/bin/ruby', 'Resources/profile-summaries.rb'],
                                input=json.dumps(values).encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(b'NEVER_EMIT_SECRET', result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_counts_block_flow_and_external_providers_without_resolving_them(self):
        rows = self.summaries([
            'proxies:\n - {name: NEVER_EMIT_SECRET, type: http, password: NEVER_EMIT_SECRET}\n - {type: socks5}\n',
            'proxies: []\nproxy-providers: {remote: {url: "https://NEVER_EMIT_SECRET"}}',
            'proxies: [{type: http}, {type: http}]',
            'proxy-providers: {remote: {type: file, path: NEVER_EMIT_SECRET}}',
        ])
        self.assertEqual(rows, [
            dict(nodeCount=2, httpCount=1, providerCount=0),
            dict(nodeCount=0, httpCount=0, providerCount=1),
            dict(nodeCount=2, httpCount=2, providerCount=0),
            dict(nodeCount=0, httpCount=0, providerCount=1),
        ])

    def test_invalid_yaml_is_unknown_not_zero_and_does_not_abort_other_entries(self):
        invalid = ['proxies: [NEVER_EMIT_SECRET',
                   'proxies: []\nproxies: [{type: http}]',
                   'proxies: []\n---\nproxies: []',
                   'proxies: &x []\nproxy-providers: *x',
                   'proxies: {NEVER_EMIT_SECRET: value}',
                   'proxies: [!ruby/object:Secret {}]',
                   'proxies: [NEVER_EMIT_SECRET]', 'dns: {}', 'x' * 2_000_001]
        rows = self.summaries(invalid + ['proxies: []'])
        for row in rows[:-1]:
            self.assertIsNone(row.get('nodeCount'))
            self.assertIn('errorCode', row)
        self.assertEqual(rows[-1], dict(nodeCount=0, httpCount=0, providerCount=0))


if __name__ == '__main__':
    unittest.main()
