require 'yaml'
require 'json'
require 'digest'
# Emit only fixed diagnostic codes/counts, never YAML, credentials or exception text.
def reject(code, count=nil)
  result={errorCode:code}
  result[:nodeCount]=count unless count.nil?
  puts JSON.generate(result)
  exit 1
end
begin
  raw = ARGV.fetch(0) == '--stdin' ? STDIN.read(2_000_001) : File.binread(ARGV.fetch(0))
  reject('oversized') if raw.bytesize > 2_000_000
  stream = Psych.parse_stream(raw)
  reject('yaml-documents') unless stream.children.length == 1
  walk = lambda do |node|
    if node.is_a?(Psych::Nodes::Mapping)
      keys=node.children.each_slice(2).map{|k,v| reject('yaml-key') unless k.is_a?(Psych::Nodes::Scalar); k.value}
      reject('yaml-duplicate') if keys.uniq.length != keys.length
    end
    (node.children || []).each{|child| walk.call(child)}
  end
  walk.call(stream.children.first)
  d = YAML.safe_load(raw, permitted_classes: [], aliases: false)
  reject('root-shape') unless d.is_a?(Hash)
  nodes=d['proxies']
  reject('proxies-shape') unless nodes.is_a?(Array)
  chain_nodes=nodes.select{|x| x.is_a?(Hash) && x['type']=='http' && x['dialer-proxy'].is_a?(String) && !x['dialer-proxy'].empty?}
  chain=nil
  if chain_nodes.length==1
    n=chain_nodes.first
    groups=d['proxy-groups'] || []
    reject('chain-shape') unless groups.is_a?(Array) && (nodes+groups).all?{|x| x.is_a?(Hash) && x['name'].is_a?(String)}
    all=nodes+groups
    reject('chain-shape') unless all.map{|x|x['name']}.uniq.length==all.length
    topology={}
    reachable=lambda do |name,seen|
      reject('chain-shape') if seen.include?(name) || seen.length>8
      item=all.find{|x|x['name']==name}
      return [] unless item
      return [item] if nodes.include?(item)
      reject('chain-selector') unless item['type']=='select'
      members=item['proxies'] || []
      reject('chain-shape') unless members.is_a?(Array) && members.all?{|x|x.is_a?(String)}
      members=members+nodes.reject{|x|x==n}.map{|x|x['name']} if item['include-all']==true || item['include-all-proxies']==true
      topology[name]=members.uniq
      members.uniq.flat_map{|x|reachable.call(x,seen+[name])}
    end
    entries=reachable.call(n['dialer-proxy'],[n['name']]).uniq.select do |e|
      %w[vless vmess trojan ss http socks5].include?(e['type']) &&
      e['server'].is_a?(String) && !e['server'].empty? && e['server'].bytesize<=253 && e['server'].match?(/\A[a-zA-Z0-9.-]+\z/) &&
      e['port'].is_a?(Integer) && e['port'].between?(1,65535) &&
      [nil,'','tcp','ws','http','h2','grpc'].include?(e['network']) &&
      !e['dialer-proxy'] && !e['interface-name'] && !e['routing-mark'] && !e['plugin'] &&
      e['tfo']!=true && e['mptcp']!=true
    end
    reject('chain-entry') if entries.empty?
    reject('chain-size') if entries.length>128 || entries.any?{|e| e['name'].bytesize>192 || e['server'].bytesize>253}
    chain={dialer:n['dialer-proxy'],groups:topology,entries:entries.map{|e|{name:e['name'],type:e['type'],server:e['server'],port:e['port']}}}
    reject('chain-size') if JSON.generate(chain).bytesize>28000
  else
    reject('providers') unless (d['proxy-providers'] || {}).empty?
    reject('node-count',nodes.length) unless nodes.length == 1
    n=nodes.first
  end
  reject('node-shape') unless n.is_a?(Hash)
  reject('node-type') unless n['name'].is_a?(String) && !n['name'].strip.empty? && n['type']=='http'
  reject('transport') if n['tls']==true || n['udp']==true || (n['dialer-proxy'] && !chain) || n['interface-name'] || n['routing-mark']
  reject('endpoint') unless n['server'].is_a?(String) && n['server'].match?(/\A[0-9]+(?:\.[0-9]+){3}\z/)
  reject('endpoint') unless n['server'].split('.').all? {|part| part.to_i.between?(0,255) && part.to_i.to_s == part }
  reject('port') unless n['port'].is_a?(Integer) && n['port'].between?(1,65535)
  reject('mode') unless ['rule','global'].include?(d['mode'])
  reject('rules') unless (d['rules'] || []).is_a?(Array) && (d['rules'] || []).all? {|r| r.is_a?(String)}
  puts JSON.generate({name:n['name'],type:n['type'],server:n['server'],port:n['port'],numeric:true,tunDevice:(d['tun']||{})['device'].to_s,chain:chain,fingerprint:Digest::SHA256.hexdigest(raw)})
rescue Psych::Exception, ArgumentError, EncodingError
  reject('yaml-invalid')
rescue StandardError
  reject('reader-error')
end
