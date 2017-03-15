require 'resolv'
require 'net/http'
require 'uri'

class Ipcheck

  def initialize()
  end
  
  def url_valid?(new_string)
    begin
      url = URI.parse(URI.encode(new_string))
      req = Net::HTTP.new(url.host, url.port)
      req.use_ssl = (url.scheme == 'https')
      req.verify_mode = OpenSSL::SSL::VERIFY_NONE #I know this is normally bad, but we just want to connect, we don't care about the security of the connection. Please don't hate me!
      path = url.path if ! url.path.empty? #use a path if available
      res = req.request_head(path || '/')
      res.code != "404" #false if returns 404
    rescue Errno::ENOENT
      false #false if can't find the server
    rescue OpenSSL::SSL::SSLError
      false #ssl can't connect
    rescue Net::OpenTimeout
      false #connection timed out, likely target is offline
    end
  end

  def url_body(n)
  
    n = URI.parse(n)
    Net::HTTP.start(n.host, n.port,
    :use_ssl => n.scheme == 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
    request = Net::HTTP::Get.new(n.request_uri)
    response = http.request(request)
    response.body
    end
  end
  
  def check(list)
    urls = Array.new #Array to store the results
    ipPhish = Array.new
    list.each do |url| #go through the input list and get each line, then do some changes to make the URL readable
      urls << url
      url.gsub!(/\s.+/, '')
      url.chomp!
      unless url.to_s.empty? #ignore blank lines
        domainNoScheme = url.sub(/\Ahttps?:\/\//,"") #strip the scheme and any trailing bits
        domain = domainNoScheme.sub(/(?=\/).+/,"")
        unless ipPhish.include? "#{domain}" #ignore duplicate domains
          begin
            ip = Resolv.new.getaddress(domain) #try to get the ip
            rescue Resolv::ResolvError #unable to get ip
            ip = "Error, unable to resolve hostname."
          end
          urls << ip
          #check to see if the urls will work with the ip subbed for the url
          if ip != "Error, unable to resolve hostname." #ignore ones that are offline or otherwise invalid
            new_url = url.sub("#{domain}","#{ip}")
            ip_phish = url_valid?("#{new_url}")
            if ip_phish   
              o = url_body("#{url}")
              n = url_body("#{new_url}")
              if o == n #if the old and new urls match then it is an ip phish
                urls << ip_phish
              else
                urls << "Mismatch in response bodies - not an IP phish" #the original and the new are not the same. Therefore, no IP phish
              end
            else
              urls << "false"
            end
          end
          ipPhish << urls.clone
          urls.clear
        end
      end
    end
  return ipPhish
  end
end
