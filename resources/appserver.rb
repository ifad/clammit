#!/usr/bin/env ruby
#
# This is a very simple sinatra app to test receiving a forwarded
# file from clammit.
#
#

require 'sinatra'

set :port, 6200

post '*' do
  puts "-------- the file ----------------------"
  puts request[:qqfile][:tempfile].read
  puts "-------- the file ----------------------"
  "It works!"
end
