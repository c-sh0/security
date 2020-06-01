#
# Simple script to Quicky parse rapid7 project sonar data using sift
# https://opendata.rapid7.com
#
# sift: (grep on steroids, grep alternative that aims for both speed and flexibility)
# https://sift-tool.org/download
#
# * Uncompressed sonar data is in json format
#
# * Single file/domain search:
#	zcat <file> | grep '.DOMAIN_NAME' | jq -r '"\(.name),\(.value)"'
#
# ./sonar_parse.sh ./domains_list.txt
#
_sift_bin='/usr/bin/sift'
_sonar_files='./sonar_files/*.json'
_out_dir='./out'
_domains_file=${1}

if [ "$#" -ne 1 ]; then
        echo "${0} <domains file>"
        exit -1
fi

rm -f ${_out_dir}/*
for _domain in `cat ${_domains_file}`; do
	echo "Searching $_domain ..."
	${_sift_bin} --no-line-number --no-filename --literal ${_domain} ${_sonar_files} >> ${_out_dir}/${_domain}.json &
done

