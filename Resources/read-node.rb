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
  reject('providers') unless (d['proxy-providers'] || {}).empty?
  nodes=d['proxies']
  reject('proxies-shape') unless nodes.is_a?(Array)
  reject('node-count',nodes.length) unless nodes.length == 1
  n=nodes.first
  reject('node-shape') unless n.is_a?(Hash)
  reject('node-type') unless n['name'].is_a?(String) && !n['name'].strip.empty? && n['type']=='http'
  reject('transport') if n['tls']==true || n['udp']==true || n['dialer-proxy'] || n['interface-name'] || n['routing-mark']
  reject('endpoint') unless n['server'].is_a?(String) && n['server'].match?(/\A[0-9]+(?:\.[0-9]+){3}\z/)
  reject('endpoint') unless n['server'].split('.').all? {|part| part.to_i.between?(0,255) && part.to_i.to_s == part }
  reject('port') unless n['port'].is_a?(Integer) && n['port'].between?(1,65535)
  reject('mode') unless ['rule','global'].include?(d['mode'])
  reject('rules') unless (d['rules'] || []).is_a?(Array) && (d['rules'] || []).all? {|r| r.is_a?(String)}
  puts JSON.generate({name:n['name'],type:n['type'],server:n['server'],port:n['port'],numeric:true,tunDevice:(d['tun']||{})['device'].to_s,fingerprint:Digest::SHA256.hexdigest(raw)})
rescue Psych::Exception, ArgumentError, EncodingError
  reject('yaml-invalid')
rescue StandardError
  reject('reader-error')
end
