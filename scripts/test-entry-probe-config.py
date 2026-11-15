#!/usr/bin/env python3
"""Offline boundary tests. Fixtures are synthetic; never read user profiles."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'Resources/prepare-entry-probe.rb'
NODE = {'alterId': 0, 'cipher': 'auto', 'encryption': 'none', 'flow': '',
        'name': 'synthetic entry', 'network': 'ws', 'port': 443,
        'server': 'entry.example.com', 'servername': 'tls.example.com',
        'skip-cert-verify': True, 'tls': True, 'type': 'vless', 'udp': True,
        'uuid': '01234567-89ab-cdef-0123-456789abcdef',
        'ws-opts': {'headers': {'Host': 'front.example.com'}, 'path': '/synthetic'}}

class EntryProbeConfigTests(unittest.TestCase):
    def invoke(self, node=None, raw=None, **changes):
        if raw is None:
            raw = json.dumps({'proxies': [copy.deepcopy(NODE if node is None else node)],
                              'tun': {'enable': True}, 'external-controller': '0.0.0.0:9090',
                              'dns': {'enable': True, 'listen': ':53'},
                              'proxy-providers': {'unused': {'url': 'https://invalid.example'}},
                              'rules': ['GEOIP,CN,DIRECT'], 'ntp': {'enable': True}})
        request = dict(yaml=raw, nodeName='synthetic entry', entryIPv4='8.8.4.4', physical='en0')
        request.update(changes)
        proc = subprocess.run(['ruby', str(SCRIPT)], input=json.dumps(request), text=True,
                              capture_output=True, timeout=8)
        self.assertEqual(proc.stderr, '', 'extractor must not emit private diagnostics')
        self.assertTrue(proc.stdout.strip(), 'extractor must return a structured result')
        return proc, json.loads(proc.stdout), raw

    def rejection(self, **kwargs):
        proc, result, _ = self.invoke(**kwargs)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(set(result), {'errorCode'})
        self.assertRegex(result['errorCode'], r'^[a-z-]+$')

    def test_tcp_reality_and_trojan_preserve_authentication(self):
        node = copy.deepcopy(NODE)
        node.pop('ws-opts'); node['network']='tcp'; node['flow']='xtls-rprx-vision'
        node['reality-opts']={'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE','short-id':'aabb'}
        node['client-fingerprint']='chrome'; node['alpn']=['h2','http/1.1']; node['packet-encoding']='xudp'
        proc,result,_=self.invoke(node=node)
        self.assertEqual(proc.returncode,0,result)
        self.assertEqual(result['config']['proxies'][0]['reality-opts'],node['reality-opts'])
        for network in ('tcp','ws'):
            n=dict(name='synthetic entry',type='trojan',server='entry.example.com',port=443,password='synthetic-password',network=network)
            if network=='ws': n['ws-opts']={'headers':{'Host':'different.example.com'},'path':'/x'}
            proc,result,_=self.invoke(node=n)
            self.assertEqual(proc.returncode,0,result)
            self.assertEqual(result['config']['proxies'][0]['sni'],'entry.example.com')

    def test_new_protocol_boundaries(self):
        base=dict(name='synthetic entry',type='vless',server='entry.example.com',port=443,uuid=NODE['uuid'],tls=True,network='tcp')
        for key,value in [('alpn',['h3']),('alpn',[]),('client-fingerprint','unreviewed'),('flow','unknown'),('packet-encoding','unknown'),('reality-opts',{'public-key':'bad','short-id':'a'}),('reality-opts',{'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE','short-id':'aabb','other':True})]:
            n=copy.deepcopy(base);n[key]=value;self.rejection(node=n)
        n=copy.deepcopy(base);n['network']='ws';n['reality-opts']={'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE','short-id':''};self.rejection(node=n)

    def test_original_vless_shape_preserves_tls_and_host(self):
        proc, result, raw = self.invoke()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(result['fingerprint'], hashlib.sha256(raw.encode()).hexdigest())
        config = result['config']
        self.assertEqual(len(config['proxies']), 1)
        node = config['proxies'][0]
        self.assertEqual(node['name'], 'GuardEntry')
        self.assertEqual(node['server'], '8.8.4.4')
        self.assertEqual(node['interface-name'], 'en0')
        self.assertEqual(node['servername'], 'tls.example.com')
        self.assertEqual(node['ws-opts']['headers']['Host'], 'front.example.com')
        self.assertFalse(node['skip-cert-verify'])
        self.assertFalse(node['udp'])
        self.assertEqual(node['uuid'], NODE['uuid'])
        self.assertEqual(node['ws-opts']['path'], '/synthetic')

    def test_infers_missing_tls_and_ws_host_before_pin(self):
        node = copy.deepcopy(NODE)
        del node['servername']
        del node['ws-opts']['headers']
        _, result, _ = self.invoke(node=node)
        self.assertEqual(result['config']['proxies'][0]['servername'], 'entry.example.com')
        self.assertEqual(result['config']['proxies'][0]['ws-opts']['headers']['Host'], 'entry.example.com')

    def test_null_flow_is_unset_but_nonempty_flow_still_rejected(self):
        for value in (None, ''):
            node = copy.deepcopy(NODE)
            node['flow'] = value
            proc, result, _ = self.invoke(node=node)
            self.assertEqual(proc.returncode, 0, result)
            self.assertNotIn('flow', result['config']['proxies'][0])
        for value in ('xtls-rprx-vision', False, 0, [], {}):
            node = copy.deepcopy(NODE)
            node['flow'] = value
            self.rejection(node=node)

    def test_tls_fallback_uses_explicit_ws_host(self):
        for value in (None, ''):
            node = copy.deepcopy(NODE)
            if value is None:
                del node['servername']
            else:
                node['servername'] = value
            _, result, _ = self.invoke(node=node)
            self.assertEqual(result['config']['proxies'][0]['servername'], 'front.example.com')

    def test_global_side_effects_are_disabled(self):
        _, result, _ = self.invoke()
        c = result['config']
        for key in ('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port'):
            self.assertEqual(c[key], 0)
        for key in ('tun', 'dns', 'ntp', 'sniffer'):
            self.assertFalse(c[key]['enable'])
        self.assertEqual(c['dns']['listen'], '')
        self.assertEqual(c['dns']['nameserver'], [])
        self.assertEqual(c['dns']['default-nameserver'], ['127.0.0.1:1'])
        self.assertEqual(c['dns']['proxy-server-nameserver'], [])
        self.assertEqual(c['dns']['direct-nameserver'], [])
        self.assertEqual(c['dns']['fallback'], [])
        for key in ('listeners', 'tunnels', 'proxy-groups', 'rules'):
            self.assertEqual(c[key], [])
        for key in ('proxy-providers', 'rule-providers', 'hosts'):
            self.assertEqual(c[key], {})
        for key in ('external-controller', 'external-controller-tls', 'external-controller-unix',
                    'external-controller-pipe', 'external-ui', 'external-ui-url'):
            self.assertEqual(c[key], '')
        self.assertFalse(c['geo-auto-update'])
        self.assertEqual(c['profile'], {'store-selected': False, 'store-fake-ip': False})
        self.assertFalse(c['allow-lan'])
        self.assertFalse(c['ipv6'])
        self.assertNotIn('script', c)

    def test_http_socks_tcp_auth_preserved(self):
        for kind in ('http', 'socks5'):
            node = dict(name='synthetic entry', type=kind, server='entry.example.com' if kind == 'http' else '8.8.4.4',
                        port=443, username='synthetic-user', password='synthetic-password', tls=True)
            _, result, _ = self.invoke(node=node)
            out = result['config']['proxies'][0]
            self.assertEqual(out['username'], 'synthetic-user')
            self.assertEqual(out['password'], 'synthetic-password')
            if kind == 'http':
                self.assertEqual(out['sni'], 'entry.example.com')
            else:
                self.assertNotIn('sni', out)
            self.assertFalse(out['skip-cert-verify'])

    def test_socks_tls_cannot_override_certificate_identity(self):
        node = dict(name='synthetic entry', type='socks5', server='entry.example.com', port=443, tls=True)
        self.rejection(node=node)
        node['server'] = '8.8.4.4'
        node['sni'] = 'entry.example.com'
        self.rejection(node=node)

    def test_plaintext_credentials_cannot_be_redirected_to_candidate(self):
        for kind in ('http', 'socks5'):
            node = dict(name='synthetic entry', type=kind, server='entry.example.com',
                        port=1080, username='synthetic-user', password='synthetic-password')
            self.rejection(node=node)
            node['server'] = '8.8.8.8'
            self.rejection(node=node)
            node['server'] = '8.8.4.4'
            proc, result, _ = self.invoke(node=node)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(result['config']['proxies'][0]['server'], '8.8.4.4')
            self.assertFalse(result['config']['proxies'][0]['tls'])

    def test_lowercase_ws_host_preserved_and_duplicate_host_rejected(self):
        node = copy.deepcopy(NODE)
        node['ws-opts']['headers'] = {'host': 'case.example.com'}
        _, result, _ = self.invoke(node=node)
        self.assertEqual(result['config']['proxies'][0]['ws-opts']['headers'], {'Host': 'case.example.com'})
        node['ws-opts']['headers']['Host'] = 'other.example.com'
        self.rejection(node=node)

    def test_unsafe_or_unknown_node_options_rejected(self):
        for key, value in [('dialer-proxy', 'other'), ('plugin', 'obfs'), ('plugin-opts', {}),
                           ('interface-name', 'utun1'), ('routing-mark', 1), ('tfo', True),
                           ('mptcp', True), ('certificate', '/tmp/private'), ('unknown', 'secret')]:
            with self.subTest(key=key):
                node = copy.deepcopy(NODE); node[key] = value
                self.rejection(node=node)

    def test_transport_and_field_validation(self):
        for key, value in [('network', 'grpc'), ('tls', False), ('type', 'trojan'),
                           ('flow', 'xtls-rprx-vision'), ('uuid', 'private-invalid'),
                           ('port', True), ('port', '443'), ('port', 0), ('port', 65536),
                           ('servername', '/tmp/cert'), ('server', '127.0.0.1'),
                           ('alterId', 1), ('cipher', 'aes-128-gcm'), ('encryption', 'invalid')]:
            with self.subTest(key=key, value=value):
                node = copy.deepcopy(NODE); node[key] = value
                self.rejection(node=node)
        for ws in ({'path': 'relative'}, {'path': '/x\r\nHeader: bad'},
                   {'path': '/', 'max-early-data': 12},
                   {'headers': {'Host': 'ok.example', 'Authorization': 'secret'}},
                   {'headers': {'Host': ['bad']}}, {'headers': {'Host': 'bad\r\n'}}):
            node = copy.deepcopy(NODE); node['ws-opts'] = ws
            self.rejection(node=node)

    def test_public_ipv4_and_physical_interface(self):
        for ip in ('127.0.0.1', '10.0.0.1', '169.254.1.1', '192.168.1.1', '172.16.0.1',
                   '100.64.1.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '8.8.8.08',
                   '8.8.8.256', '8.8.8.8\n', 'example.com', '::1', '198.18.0.1', '192.0.2.1'):
            with self.subTest(ip=ip): self.rejection(entryIPv4=ip)
        for interface in ('utun0', 'lo0', 'en0\n', 'en0;id', '', 'en01', None):
            with self.subTest(interface=interface): self.rejection(physical=interface)

    def test_ambiguous_or_unsafe_yaml_fails_without_secret(self):
        raws = ['proxies: []\nproxies: []', '---\nproxies: []\n---\nproxies: []',
                'proxies: &private []\ncopy: *private',
                'proxies: [{name: private, name: private}]', '!!ruby/object:Object {}',
                'proxies: []', 'null', '[private]', '{',
                json.dumps({'proxies': [NODE, NODE]}),
                'proxies: []\n? [private, key]\n: value']
        for raw in raws:
            with self.subTest(raw=raw): self.rejection(raw=raw)
        self.rejection(nodeName='not present')
        self.rejection(raw='x' * 2_000_001)

if __name__ == '__main__':
    unittest.main()
