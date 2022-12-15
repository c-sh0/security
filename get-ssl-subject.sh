#!/bin/sh
#
HOSTS_F=${1}
LOG_F='ssl-subject.out'

rm -f ${LOG_F}
for  _host in `cat ${HOSTS_F}`; do
        S=`(timeout 5 openssl s_client -connect ${_host}:443 </dev/null 2>/dev/null) | grep "subject="`
        echo "${_host}:${S}" >> ${LOG_F}
        echo "${_host}:${S}"
done
