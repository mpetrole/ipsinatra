require 'sinatra'
require 'thin'
require 'digest'
require_relative 'ipcheck'
require_relative 'malcheck/malware.rb'
require_relative 'iterate/iterate.rb'

set :static, true
set :public_folder, "ipsinatra"
set :views, "views"

use Rack::Auth::Basic, "Restricted Area" do |username, password|
  unless Digest::SHA256.hexdigest("#{password}") != 'c5acd59bf2999f29e22dbf39306a29a869de024caef060452b9d6ab90a473218' #put sha256 encrypted password here
  username == 'soc' and password == password #put username in the quotes
  end
end

get '/' do
  erb :index
end

get '/ip' do
  erb :ip
end

get '/mal' do
  erb :mal
end

get '/iter' do
  erb :it
end

post '/ipinput' do
  res = Hash.new("")
  u = params[:urls].lines("\n")
  ls = Ipcheck.new()
  res = ls.check(u)
  erb :ipinput, :locals => {'res' => res}
end

post '/malcheck' do
  ip = params[:ips].lines("\n")
  conn = Connect.new(ip)
  result = conn.check
  erb :malout, :locals => {'result' => result}
end

post '/iterate' do
  url = params[:url]
  conn = Iterate.new(url)
  conn.construct
  res = conn.check
  erb :itout, :locals => {'res' => res}
end

post '/ip' do
  erb :ip
end

post '/mal' do
  erb :mal
end

post '/it' do
  erb :it
end

File.open('ip.pid', 'w') {|f| f.write Process.pid }
