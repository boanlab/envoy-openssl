load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"]) 

cmake(
   name = "bssl-compat",
   lib_source = ":srcs",
   out_shared_libs = ["libbssl-compat.so"],
   out_static_libs = [],
   visibility = ["//visibility:public"],
   generate_crosstool_file = False,
   env = { "Clang_ROOT": "/usr/lib/llvm" },
   cache_entries = {
     "OPENSSL_USE_STATIC_LIBS": "OFF",
     "BUILD_SHARED_LIBS": "ON",
     "CMAKE_BUILD_TYPE": "Release",
     "CMAKE_C_FLAGS": "-march=native -fomit-frame-pointer",
     "CMAKE_CXX_FLAGS": "-march=native -fomit-frame-pointer",
   },
   build_args = ["-j"],
   linkopts = [
       "-Wl,--no-undefined",
       "-Wl,--as-needed",
   ],
)

alias(
    name = "crypto",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)

alias(
    name = "ssl",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)