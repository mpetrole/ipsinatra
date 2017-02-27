require 'sinatra'
require 'thin'
require_relative 'ipcheck'

set :static, true
set :public_folder, "ipsinatra"
set :views, "views"

use Rack::Auth::Basic, "Restricted Area" do |username, password|
  username == 'soc' and password == 'K1x1CP9iXy68tGjIegeX'
end

get '/' do
  <p>"Welcome to my server =)"</p>
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
