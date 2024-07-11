#!/bin/bash
  
cd /usr/sbin

echo "please start shadow and app or hook 41032"

ps aux | grep frida | grep -v "grep\|bash" | awk '{print $2}' | xargs -r kill
echo "frida server killed"

ps aux | grep llmerfs | grep -v "grep\|bash" | awk '{print $2}' | xargs -r kill

mv llmerfs frida-server

frida-server -l 127.0.0.1:41032 &

