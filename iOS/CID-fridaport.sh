#!/bin/bash
  
cd /usr/sbin

if mv frida-server llmerfs; then
    echo "frida-server moved"
else
    echo "frida-server not found, but not abort"
fi

ps aux | grep frida | grep -v "grep\|bash" | awk '{print $2}' | xargs -r kill

echo "frida server killed"

ps aux | grep llmerfs | grep -v "grep\|bash" | awk '{print $2}' | xargs -r kill

echo "please start shadow and start app and hook 27042"

llmerfs -l 127.0.0.1:27042 &

