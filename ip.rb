require 'sinatra'
require 'thin'
require 'digest'
require_relative 'ipcheck'

set :static, true
set :public_folder, "ipsinatra"
set :views, "views"

use Rack::Auth::Basic, "Restricted Area" do |username, password|
  unless Digest::SHA256.hexdigest("#{password}") != '' #put sha256 encrypted password here
  username == '' and password == password #put username in the quotes
  end
end

get '/' do
  "Welcome to my server =)"
end

get '/ip' do
  erb :ip
end

post '/ipinput' do
  res = Hash.new("")
  u = params[:urls].lines("\n")
  list = Ipcheck.new()
  res = list.check(u)
  erb :ipinput, :locals => {'res' => res}
end

post '/ip' do
  erb :ip
end
