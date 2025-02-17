#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --sed '/#include <openssl\/base\.h>/a#include <ossl/openssl/stack.h>' \
  --uncomment-macro STACK_OF \
  --uncomment-macro DECLARE_STACK_OF \
  --uncomment-macro DEFINE_NAMED_STACK_OF \
  --uncomment-macro DEFINE_STACK_OF \
  --uncomment-macro DEFINE_CONST_STACK_OF \
  --uncomment-regex 'template <typename Stack>'\
  --uncomment-regex 'namespace internal {' 'template <typename T>' 'struct StackTraits \{\};' '}' \
  --uncomment-macro BORINGSSL_DEFINE_STACK_TRAITS \
  --uncomment-macro BORINGSSL_DEFINE_STACK_OF_IMPL \
  --uncomment-struct DeleterImpl \
  --uncomment-struct DeleterImpl \
  --uncomment-class StackIteratorImpl \
  --uncomment-using StackIterator \
  --uncomment-regex-range 'inline\>' '}' \
  --uncomment-regex-range 'inline\>.*\<begin\>' '}' \
  --uncomment-regex-range 'inline\>.*\<end\>' '}' \
  --uncomment-regex '}$' \
  --uncomment-regex 'namespace internal {' \
  --uncomment-regex '}  // namespace internal' \
  --sed '/^\/\/ } _STACK;$/atypedef struct ossl_stack_st _STACK;' \
  --uncomment-typedef OPENSSL_sk_free_func \
  --uncomment-typedef OPENSSL_sk_copy_func \
  --uncomment-typedef OPENSSL_sk_cmp_func \
  --uncomment-typedef OPENSSL_sk_call_free_func \
  --uncomment-typedef OPENSSL_sk_call_copy_func \
  --uncomment-typedef OPENSSL_sk_call_cmp_func \
  --uncomment-func-decl sk_new \
  --uncomment-func-decl sk_new_null \
  --uncomment-func-decl sk_num \
  --uncomment-func-decl sk_zero \
  --uncomment-func-decl sk_value \
  --uncomment-func-decl sk_set \
  --uncomment-func-decl sk_free \
  --uncomment-func-decl sk_pop_free_ex \
  --uncomment-func-decl sk_insert \
  --uncomment-func-decl sk_delete \
  --uncomment-func-decl sk_delete_ptr \
  --uncomment-func-decl sk_find \
  --uncomment-func-decl sk_shift \
  --uncomment-func-decl sk_push \
  --uncomment-func-decl sk_pop \
  --uncomment-func-decl sk_dup \
  --uncomment-func-decl sk_sort \
  --uncomment-func-decl sk_is_sorted \
  --uncomment-func-decl sk_set_cmp_func \
  --uncomment-func-decl sk_deep_copy \
  