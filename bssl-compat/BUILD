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
       # "CMAKE_BUILD_WITH_INSTALL_RPATH": "ON",
       # "CMAKE_INSTALL_RPATH_USE_LINK_PATH": "ON",
       "CMAKE_BUILD_TYPE": "Debug",  # Debug 모드 설정
       "CMAKE_CXX_FLAGS_DEBUG": "-g3 -O0 -fno-omit-frame-pointer -fno-inline -fno-eliminate-unused-debug-types -gdwarf-4",  # 디버그 플래그
       "CMAKE_C_FLAGS_DEBUG": "-g3 -O0 -fno-omit-frame-pointer -fno-inline -fno-eliminate-unused-debug-types -gdwarf-4",    # 디버그 플래그
       #"CMAKE_EXE_LINKER_FLAGS": "-rdynamic", # Debug 모드 설정
       #"CMAKE_SHARED_LINKER_FLAGS": "-rdynamic", # Debug 모드 설정
       # "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", # Debug 모드 설정
   },
   build_args = ["-j"],
   linkopts = [
       # "-Wl,--no-as-needed",
       # "-Wl,--allow-shlib-undefined",
       # "-g", # Debug 모드 설정
       # "-Wl,--export-dynamic", # Debug 모드 설정
       # "-Wl,--build-id", # Debug 모드 설정
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