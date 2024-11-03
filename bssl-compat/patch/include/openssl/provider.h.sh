#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl OSSL_PROVIDER_query_operation \
  --uncomment-typedef-redef ossl_OSSL_PROVIDER_query_operation \

  