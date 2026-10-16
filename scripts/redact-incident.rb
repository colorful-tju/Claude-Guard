#!/usr/bin/ruby
# Read-only collector redaction. Never emit the raw input on parse failure.
require 'json'
begin
  source = JSON.parse(File.binread(ARGV.fetch(0)))
  def redact(value)
    case value
    when Hash
      value.to_h { |k, v| [k, %w[token ownReference initialReferences allowedStates].include?(k) ? '[REDACTED]' : redact(v)] }
    when Array then value.map { |v| redact(v) }
    else value
    end
  end
  puts JSON.pretty_generate(redact(source))
rescue StandardError
  warn 'Private JSON unreadable; raw content withheld'
  exit 1
end
