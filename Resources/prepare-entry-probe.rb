# PRIVATE successful output: contains proxy credentials. Never log stdout.
# Pure stdin -> stdout extraction; no files, sockets, subprocesses or core invocation.
require 'yaml'
require 'json'
require 'digest'
require 'ipaddr'
require 'base64'

def reject(code)
  puts JSON.generate({errorCode: code})
  exit 1
end

def public_ipv4?(value)
  return false unless value.is_a?(String) && value.match?(/\A[0-9]+(?:\.[0-9]+){3}\z/)
  return false unless value.split('.').all? { |p| p.to_i.between?(0,255) && p.to_i.to_s == p }
  ip = IPAddr.new(value)
  # Exclude private, link-local, shared, multicast, reserved and documentation ranges.
  %w[0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
     172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16
     198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4].none? { |r| IPAddr.new(r).include?(ip) }
end

def host?(value)
  return false unless value.is_a?(String) && value.bytesize.between?(1,253)
  return public_ipv4?(value) if value.match?(/\A[0-9.]+\z/)
  value.split('.', -1).length >= 2 && value.split('.', -1).all? { |label| label.bytesize.between?(1,63) && label.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\z/) }
end

begin
  input = STDIN.read(12_000_001)
  reject('oversized') if input.bytesize > 12_000_000
  request = JSON.parse(input)
  reject('input-shape') unless request.is_a?(Hash) && request.keys.sort == %w[entryIPv4 nodeName physical yaml]
  raw, name, ipv4, physical = request.values_at('yaml', 'nodeName', 'entryIPv4', 'physical')
  reject('input-shape') unless raw.is_a?(String) && name.is_a?(String) && name.bytesize.between?(1,192)
  reject('oversized') if raw.bytesize > 2_000_000
  reject('entry-ipv-four') unless public_ipv4?(ipv4)
  reject('physical-interface') unless physical.is_a?(String) && physical.match?(/\Aen(?:0|[1-9][0-9]{0,3})\z/)
  stream = Psych.parse_stream(raw)
  reject('yaml-documents') unless stream.children.length == 1
  walk = lambda do |ast, depth|
    reject('yaml-depth') if depth > 64
    reject('yaml-alias') if ast.is_a?(Psych::Nodes::Alias)
    if ast.is_a?(Psych::Nodes::Mapping)
      keys = ast.children.each_slice(2).map do |k, _|
        reject('yaml-key') unless k.is_a?(Psych::Nodes::Scalar)
        k.value
      end
      reject('yaml-duplicate') unless keys.uniq.length == keys.length
    end
    (ast.children || []).each { |child| walk.call(child, depth + 1) }
  end
  walk.call(stream.children.first, 0)
  data = YAML.safe_load(raw, permitted_classes: [], aliases: false)
  reject('root-shape') unless data.is_a?(Hash)
  nodes = data['proxies']
  reject('proxies-shape') unless nodes.is_a?(Array) && nodes.all? { |n| n.is_a?(Hash) && n['name'].is_a?(String) }
  reject('node-ambiguous') unless nodes.map { |n| n['name'] }.uniq.length == nodes.length
  node = nodes.find { |n| n['name'] == name }
  reject('node-missing') unless node
  kind = node['type']
  reject(%w[tuic hysteria hysteria2 wireguard].include?(kind) ? 'node-type-udp' : 'node-type') unless %w[vless trojan http socks5].include?(kind)
  allowed = %w[name type server port network tls skip-cert-verify udp]
  allowed += if kind == 'vless'
    %w[uuid alterId cipher encryption flow servername ws-opts reality-opts client-fingerprint alpn packet-encoding]
  elsif kind == 'trojan'
    %w[password sni ws-opts reality-opts client-fingerprint alpn]
  else
    %w[username password sni]
  end
  reject('node-option') unless (node.keys - allowed).empty?
  reject('endpoint') unless host?(node['server'])
  reject('port') unless node['port'].is_a?(Integer) && node['port'].between?(1,65535)
  %w[tls udp skip-cert-verify].each { |k| reject('node-field') if node.key?(k) && ![true,false].include?(node[k]) }
  out = {'name'=>'GuardEntry', 'type'=>kind, 'server'=>ipv4, 'port'=>node['port'],
         'interface-name'=>physical, 'udp'=>false}
  if %w[vless trojan].include?(kind)
    network = node.fetch('network','tcp')
    reject('transport') unless %w[tcp ws].include?(network)
    reject('transport') unless kind == 'trojan' ? node['tls'] != false : node['tls'] == true
    reject('transport') if network == 'tcp' && node.key?('ws-opts')
    if kind == 'vless'
      reject('uuid') unless node['uuid'].is_a?(String) && node['uuid'].match?(/\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z/)
      reject('node-field') if node.key?('alterId') && node['alterId'] != 0
      reject('node-field') if node.key?('cipher') && !['auto','none',''].include?(node['cipher'])
      reject('node-field') if node.key?('encryption') && !['','none'].include?(node['encryption'])
      flow=node['flow']
      reject('flow') unless [nil,'','xtls-rprx-vision'].include?(flow) && (flow != 'xtls-rprx-vision' || network == 'tcp')
      out['uuid']=node['uuid'];out['flow']=flow unless flow.nil? || flow.empty?
      encoding=node['packet-encoding']
      reject('packet-encoding') unless [nil,'','xudp','packetaddr'].include?(encoding)
      out['packet-encoding']=encoding unless encoding.nil? || encoding.empty?
    else
      password=node['password']
      reject('credentials') unless password.is_a?(String) && password.bytesize.between?(1,4096) && !password.match?(/[\x00\r\n]/)
      out['password']=password
    end
    if node.key?('client-fingerprint')
      reject('client-fingerprint') unless %w[chrome firefox safari ios android edge random].include?(node['client-fingerprint'])
      out['client-fingerprint']=node['client-fingerprint']
    end
    if node.key?('alpn')
      alpn=node['alpn']
      reject('alpn') unless alpn.is_a?(Array) && !alpn.empty? && alpn.length<=2 && alpn.uniq==alpn && (alpn-%w[h2 http/1.1]).empty?
      out['alpn']=alpn
    end
    if node.key?('reality-opts')
      reality=node['reality-opts']
      reject('reality') unless network=='tcp' && reality.is_a?(Hash) && (reality.keys-%w[public-key short-id]).empty?
      key=reality['public-key'];short=reality.fetch('short-id','')
      reject('reality') unless key.is_a?(String) && key.match?(/\A[A-Za-z0-9_-]{43}\z/) && Base64.urlsafe_decode64(key).bytesize==32 && Base64.urlsafe_encode64(Base64.urlsafe_decode64(key),padding:false)==key
      reject('reality') unless short.is_a?(String) && short.bytesize<=16 && short.bytesize.even? && short.match?(/\A[0-9a-fA-F]*\z/)
      reject('client-fingerprint') unless out['client-fingerprint']
      out['reality-opts']={'public-key'=>key,'short-id'=>short}
    end
    sni_key=kind=='trojan' ? 'sni' : 'servername'
    sni=node[sni_key]
    explicit_host=nil
    if network=='ws'
      ws=node.fetch('ws-opts',{})
      reject('websocket') unless ws.is_a?(Hash) && (ws.keys-%w[path headers]).empty?
      path=ws.fetch('path','/')
      reject('websocket') unless path.is_a?(String) && path.bytesize.between?(1,4096) && path.start_with?('/') && !path.match?(/[\x00-\x20\x7f]/)
      headers=ws.fetch('headers',{})
      reject('websocket') unless headers.is_a?(Hash) && headers.keys.all?{|k| k.is_a?(String) && k.downcase=='host'} && headers.length<=1
      explicit_host=headers.values.first unless headers.empty?
      # Fixed Core defaults: Trojan's WS Host falls back to SNI, VLESS to server.
      ws_host=explicit_host || (kind=='trojan' && sni.is_a?(String) && !sni.empty? ? sni : node['server'])
      reject('websocket') unless host?(ws_host)
      out['ws-opts']={'path'=>path,'headers'=>{'Host'=>ws_host}}
    end
    sni=(kind=='vless' && network=='ws' && explicit_host ? explicit_host : node['server']) if sni.nil? || sni==''
    reject('tls-name') unless host?(sni)
    out.merge!('network'=>network,'tls'=>true,sni_key=>sni,'skip-cert-verify'=>false)
  else
    reject('transport') unless !node.key?('network') || node['network'] == 'tcp'
    %w[username password].each do |k|
      next unless node.key?(k)
      reject('credentials') unless node[k].is_a?(String) && node[k].bytesize <= 4096 && !node[k].match?(/[\x00\r\n]/)
      out[k] = node[k]
    end
    reject('tls-name') if kind == 'socks5' && node.key?('sni')
    if node['tls'] == true
      # This Core's SOCKS adapter uses server itself for TLS, without SNI override.
      reject('socks-tls-endpoint') if kind == 'socks5' && node['server'] != ipv4
      sni = node.fetch('sni', node['server'])
      reject('tls-name') unless host?(sni)
      out.merge!('tls'=>true,'skip-cert-verify'=>false)
      out['sni'] = sni if kind == 'http'
    else
      # Without authenticated TLS, never send credentials to an alternate IP.
      reject('plaintext-endpoint') unless public_ipv4?(node['server']) && node['server'] == ipv4
      reject('tls-name') if node.key?('sni')
      out['tls'] = false
    end
  end
  config = {
    'port'=>0, 'socks-port'=>0, 'mixed-port'=>0, 'redir-port'=>0, 'tproxy-port'=>0,
    'allow-lan'=>false, 'bind-address'=>'127.0.0.1', 'ipv6'=>false,
    'mode'=>'rule', 'log-level'=>'silent', 'find-process-mode'=>'off',
    'interface-name'=>physical, 'disable-keep-alive'=>true,
    'external-controller'=>'', 'external-controller-tls'=>'', 'external-controller-unix'=>'',
    'external-controller-pipe'=>'', 'external-ui'=>'', 'external-ui-url'=>'',
    'external-ui-name'=>'', 'secret'=>'',
    'tun'=>{'enable'=>false,'auto-route'=>false,'auto-redirect'=>false,'auto-detect-interface'=>false,'dns-hijack'=>[]},
    'dns'=>{'enable'=>false,'listen'=>'','ipv6'=>false,'use-hosts'=>false,'use-system-hosts'=>false,
            # Core validates this even with DNS disabled. No public/system bootstrap.
            'default-nameserver'=>['127.0.0.1:1'],'nameserver'=>[],'fallback'=>[],'proxy-server-nameserver'=>[],
            'direct-nameserver'=>[],'nameserver-policy'=>{},'fallback-filter'=>{'geoip'=>false,'geosite'=>[],'ipcidr'=>[],'domain'=>[]}},
    'ntp'=>{'enable'=>false,'write-to-system'=>false}, 'sniffer'=>{'enable'=>false},
    'profile'=>{'store-selected'=>false,'store-fake-ip'=>false},
    'geo-auto-update'=>false, 'geodata-mode'=>false, 'geox-url'=>{},
    'hosts'=>{}, 'listeners'=>[], 'tunnels'=>[], 'proxy-providers'=>{}, 'rule-providers'=>{},
    'proxies'=>[out], 'proxy-groups'=>[], 'rules'=>[]
  }
  puts JSON.generate({config: config, fingerprint: Digest::SHA256.hexdigest(raw)})
rescue JSON::ParserError
  reject('input-invalid')
rescue Psych::Exception, ArgumentError, EncodingError
  reject('yaml-invalid')
rescue StandardError, SystemStackError
  reject('extractor-error')
end
