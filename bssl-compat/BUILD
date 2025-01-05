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
   env = { 
       "Clang_ROOT": "/usr/lib/llvm",
   },
   cache_entries = {
       "OPENSSL_USE_STATIC_LIBS": "OFF",
       "BUILD_SHARED_LIBS": "ON",
    #    "CMAKE_BUILD_WITH_INSTALL_RPATH": "ON",
    #    "CMAKE_INSTALL_RPATH_USE_LINK_PATH": "ON",
    #    "CMAKE_BUILD_TYPE": "Debug",  # flags for debug
    #    "CMAKE_CXX_FLAGS_DEBUG": "-g3 -O0 -fno-omit-frame-pointer -fno-inline -fno-eliminate-unused-debug-types -gdwarf-4",  # flags for debug
    #    "CMAKE_C_FLAGS_DEBUG": "-g3 -O0 -fno-omit-frame-pointer -fno-inline -fno-eliminate-unused-debug-types -gdwarf-4",    # flags for debug
    #    "CMAKE_EXE_LINKER_FLAGS": "-rdynamic", # flags for debug
    #    "CMAKE_SHARED_LINKER_FLAGS": "-rdynamic", # flags for debug
    #    "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", # flags for debug
   },
   build_args = ["-j"],
   linkopts = [
       "-Wl,--no-as-needed",
       "-Wl,--allow-shlib-undefined",
    #    "-g", # flags for debug
    #    "-Wl,--export-dynamic", # flags for debug
    #    # "-Wl,--build-id", # flags for debug
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