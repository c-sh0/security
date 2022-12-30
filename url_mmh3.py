#!/usr/bin/env python3
#
# Print MurMurHash for a givin URL
#
import argparse
import mmh3
import codecs
import requests
requests.packages.urllib3.disable_warnings()

def main():
  parser = argparse.ArgumentParser(description='URL to mmh3', epilog=" \n", formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-u','--url',  help='[url]\t:- http(s)://[host|ip]/path', dest='url', metavar='', action='store', required=True)
  cmdargs = parser.parse_args()

  ctx = {}
  ctx['url'] = cmdargs.url
  print(f"URL: {ctx['url']}")

  response = requests.get(ctx['url'],verify=False)
  urlb64   = codecs.encode(response.content,"base64")
  #print(f"URL Base64: {urlb64}")

  hash = mmh3.hash(urlb64)
  print(f"URL mmh3: {hash}")

if __name__ == "__main__":
  main()
