load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"])  # Apache 2

# Omit point : "OPENSSL_USE_STATIC_LIBS: OFF"
cmake(
    name = "bssl-compat",
    lib_source = ":srcs",
    out_shared_libs = ["libbssl-compat.so"],
    out_static_libs = [],
    visibility = ["//visibility:public"],
    generate_crosstool_file = False,
    env = { "Clang_ROOT": "/usr/lib/llvm" },
    cache_entries = {
        "BUILD_SHARED_LIBS": "ON",
        "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
    },
    linkopts = ["-ldl"],
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
