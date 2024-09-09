cc_import(
    name = "bssl-compat",
    static_library = "lib/libbssl-compat.a",
    includes = ["include/"],
    visibility = ["//visibility:public"],
)

alias(
    name = "ssl",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)

alias(
    name = "crypto",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)
