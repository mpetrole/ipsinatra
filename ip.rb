require 'sinatra'
require 'thin'
require_relative 'ipcheck'

set :static, true
set :public_folder, "ipsinatra"
set :views, "views"

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
