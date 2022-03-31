#!/bin/sh
#
# Find process information for short lived tcp connections
# Could use improvement
#
# /proc/[pid]/cmdline
# This holds the complete command line for the process, unless the whole process has been swapped out, or unless the process is a zombie.
# In either of these later cases, there is nothing in this file: i.e. a read on this file will return 0 characters. The command line arguments
# appear in this file as a set of null-separated strings, with a further null byte after the last string.
#
# /proc/[pid]/environ
# This file contains the environment for the process. The entries are separated by null characters, and there may be a null character at the end.
#
# [/csh:]>
#
if [ "$#" -ne 1 ]; then
        echo "$0 <port>"
        exit 0
fi

while [ 1 ]; do
        # get syn-sent instead ?
        #_pid=`ss -ntap -o state syn-sent "( dport = :${1} )" | awk 'BEGIN {FS = ","}; {print $2}' | cut -d= -f2 | awk 'NF'`
        #
        # get established
        _pid=`ss -ntap -o state established "( dport = :${1} )" | awk 'BEGIN {FS = ","}; {print $2}' | cut -d= -f2 | awk 'NF'`

        if [ -z ${_pid} ]; then
                continue
        else
                echo "Got PID: ${_pid} cmdline: `cat /proc/${_pid}/cmdline`"
                echo "ENV: `cat /proc/${_pid}/environ`"
                lsof -p $_pid

                _ppid=`ps -o ppid= -p $_pid | awk '{$1=$1};1'`
                echo "PPID: ${_ppid} cmdline: `cat /proc/${_ppid}/cmdline`"
                echo "ENV: `cat /proc/${_ppid}/environ`"
                lsof -p $_ppid

                # if ppid has ppid ?
                _ppid2=`ps -o ppid= -p $_ppid | awk '{$1=$1};1'`
                echo "PPID2: ${_ppid2} cmdline: `cat /proc/${_ppid2}/cmdline`"
                echo "ENV: `cat /proc/${_ppid2}/environ`"
                lsof -p $_ppid2

                # Extra Credit
                # strace the processes (if PID is a shell, snoop the session)
                echo
                echo -e "Run the following to trace the processes, (if PID is a shell, snoop the session)...\n\n"
                echo -e "PID ${_pid}:  (`cat /proc/${_pid}/cmdline`):\n\tstrace -e trace=clone,write,dup,dup2,open,close -s4096 -fp ${_pid}\n"
                echo -e "PPID ${_ppid}: (`cat /proc/${_ppid}/cmdline`)\n\tstrace -e trace=clone,write,dup,dup2,open,close -s4096 -fp ${_ppid}\n"
                echo -e "PPID2 ${_ppid2}: (`cat /proc/${_ppid2}/cmdline`)\n\tstrace -e trace=clone,write,dup,dup2,open,close -s4096 -fp ${_ppid2}\n"

                exit 1
        fi
done

