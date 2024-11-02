#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-typedef OSSL_PROVIDER; \