#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-typedef OSSL_PROVIDER \
  --uncomment-typedef OSSL_LIB_CTX \
  --uncomment-typedef OSSL_PARAM \
  --uncomment-typedef OSSL_ALGORITHM \