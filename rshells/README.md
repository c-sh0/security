# Reverse Shells and Other tricks
Collection of some common and not so common reverse shell, file upload, and download tircks without the use of standard tools.

NOTES:
* Having disk write permissions on the client is +1
* If a service is running under systemd with PrivateTmp= set, it sets up a new file system namespace for the executed processes and mounts a private /tmp directory inside it, that is not shared by processes outside of the namespace. (ie: /tmp/systemd-private*/) This is useful to secure access to temporary files of the process, but makes sharing between processes via /tmp impossible.
*  If SELinux is enabled on the client system, alot of these may not work as intended. Disable SELinux:
     
     ```[root@client]# setenforce 0```

References:<br>
https://gtfobins.github.io/<br>
https://github.com/swisskyrepo/PayloadsAllTheThings<br>
https://oshi.at/cmd<br>
