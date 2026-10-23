require 'yaml'
require 'json'

# Unprivileged picker metadata only. Never fetch providers, construct YAML
# objects, or emit node names/addresses/credentials/raw exception messages.
def summary(raw)
  return {errorCode:'unreadable'} unless raw.is_a?(String)
  return {errorCode:'oversized'} if raw.bytesize > 2_000_000
  stream=Psych.parse_stream(raw)
  return {errorCode:'yaml-invalid'} unless stream.children.length == 1
  pending=[[stream,0]]; visited=0
  until pending.empty?
    node,depth=pending.pop; visited+=1
    return {errorCode:'yaml-invalid'} if depth>64 || visited>100_000 || node.is_a?(Psych::Nodes::Alias)
    if node.is_a?(Psych::Nodes::Mapping)
      keys=node.children.each_slice(2).map{|k,v| k.is_a?(Psych::Nodes::Scalar) ? k.value : nil}
      return {errorCode:'yaml-invalid'} if keys.include?(nil) || keys.uniq.length != keys.length
    end
    (node.children || []).each{|child| pending << [child,depth+1]}
  end
  data=YAML.safe_load(raw, permitted_classes: [], aliases: false)
  return {errorCode:'shape'} unless data.is_a?(Hash)
  providers=data.fetch('proxy-providers',{})
  return {errorCode:'shape'} unless providers.is_a?(Hash)
  nodes=data.fetch('proxies',providers.empty? ? nil : [])
  return {errorCode:'shape'} unless nodes.is_a?(Array) && nodes.all?{|n| n.is_a?(Hash)}
  {nodeCount:nodes.length,httpCount:nodes.count{|n| n['type']=='http'},providerCount:providers.length}
rescue StandardError, SystemStackError
  {errorCode:'yaml-invalid'}
end

begin
  input=STDIN.read(48_100_001)
  exit 1 if input.bytesize>48_100_000
  rows=JSON.parse(input)
  exit 1 unless rows.is_a?(Array) && rows.length<=501
  puts JSON.generate(rows.map{|raw|summary(raw)})
rescue StandardError, SystemStackError
  exit 1
end
