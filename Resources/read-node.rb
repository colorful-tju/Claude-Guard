require 'yaml'
require 'json'
require 'digest'
# Safe_load rejects Ruby object tags, aliases, duplicate keys are checked separately.
raw = File.binread(ARGV.fetch(0))
raise 'oversized configuration' if raw.bytesize > 2_000_000
ast = Psych.parse(raw)
walk = lambda do |node|
  if node.is_a?(Psych::Nodes::Mapping)
    keys=node.children.each_slice(2).map{|k,v| raise 'non-scalar key' unless k.is_a?(Psych::Nodes::Scalar); k.value}
    raise 'duplicate mapping key' if keys.uniq.length != keys.length
  end
  (node.children || []).each{|child| walk.call(child)}
end
walk.call(ast)
d = YAML.safe_load(raw, permitted_classes: [], aliases: false)
raise 'unsupported root' unless d.is_a?(Hash)
raise 'external providers unsupported' unless (d['proxy-providers'] || {}).empty?
nodes = d.fetch('proxies')
# Single-node direct HTTP configuration makes name/selection ambiguity fail closed.
raise 'multiple nodes unsupported for MVP' unless nodes.is_a?(Array) && nodes.length == 1
n=nodes.first
raise 'wrong node' unless n['name'].is_a?(String) && !n['name'].strip.empty? && n['type']=='http'
raise 'additional transport unsupported' if n['tls']==true || n['udp']==true || n['dialer-proxy'] || n['interface-name'] || n['routing-mark']
raise 'unsupported endpoint' unless n['server'].is_a?(String) && n['server'].match?(/\A[0-9]+(?:\.[0-9]+){3}\z/)
raise 'invalid port' unless n['port'].is_a?(Integer) && n['port'].between?(1,65535)
raise 'direct main configuration unsupported' unless ['rule','global'].include?(d['mode'])
raise 'rule path unsupported' unless (d['rules'] || []).all? {|r| r.is_a?(String)}
puts JSON.generate({name:n['name'],type:n['type'],server:n['server'],port:n['port'],numeric:true,tunDevice:(d['tun']||{})['device'].to_s,fingerprint:Digest::SHA256.hexdigest(raw)})
