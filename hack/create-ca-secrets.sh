#!/bin/bash

usage()
{
  echo "Usage:
    $0 [-h|--help]          display this help and exit
       --ca-cert <file>     file containing the PEM encoded CA certificate
       --client-key <file>   file containing the #PKCS1 encoded private key
       --client-cert <file> file containing the PEM encoded client certificate
                            corresponding to the clinet private key
"
    exit 0
}

cacert=
key=
cert=

while [ $# != 0 ];
do
  case "$1" in
  --ca-cert)
    shift 1; cacert=$1;;
  --client-key)
    shift 1; key=$1;;
  --client-cert)
    shift 1; cert=$1;;
  -h|--help) usage;;
  *) echo "Unknown option $1"
  esac
  shift 1
done

if [ -z "$cacert" -o -z "$key" -o -z "$cert" ]; then
  echo "Incomplete arguments:"
  usage
fi

echo "ca.crt=$(cat $cacert | base64 -w 0)
client.crt=$(cat $cert | base64 -w 0)
client.key=$(cat $key | base64 -w 0)" > config/manager/.ca.secrets

echo "Secret configuration generated into: 'config/manager/.ca.secrets'"
