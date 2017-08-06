#!/bin/bash
dpkg --add-architecture i386 && apt-get update && apt-get install -y wine32
echo -e "\ndeb http://mirrors.tuna.tsinghua.edu.cn/kali  kali-rolling contrib main non-free" >>/etc/apt/sources.list 
echo -e "\ndeb http://us.archive.ubuntu.com/ubuntu trusty main universe" >>/etc/apt/sources.list
apt-get update && apt-get install  xterm monodevelop mono-complete  mingw32
gem sources --add https://gems.ruby-china.org/ --remove https://rubygems.org/
gem install rake gtk2 zerenity artii colorize
echo "XTerm*selectToClipboard:true"  >> ~/.Xdefaults
xrdb ~/.Xdefaults

 
