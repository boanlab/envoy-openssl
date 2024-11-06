load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"]) 

cmake(
    name = "bssl-compat",
    lib_source = ":srcs",
    out_shared_libs = [],
    out_static_libs = ["libbssl-compat.a"],
    visibility = ["//visibility:public"],
    generate_crosstool_file = False,
    env = { 
        "Clang_ROOT": "/usr/lib/llvm",
    },
    cache_entries = {
        "BUILD_SHARED_LIBS": "OFF",
        "OPENSSL_USE_STATIC_LIBS": "ON",
    },
    build_args = ["-j"]
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
