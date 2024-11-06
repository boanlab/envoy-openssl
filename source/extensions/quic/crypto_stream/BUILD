load(
    "@envoy_build_config//:extensions_build_config.bzl",
    "LEGACY_ALWAYSLINK",
)
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "envoy_quic_crypto_server_stream_lib",
    srcs = select({
        "@envoy//bazel:boringssl_fips": [],  # FIPS 모드에서는 소스 파일 없음
        "//conditions:default": [],
        # "//conditions:default": ["envoy_quic_crypto_server_stream.cc"],
    }),
    hdrs = select({
        "@envoy//bazel:boringssl_fips": [],  # FIPS 모드에서는 헤더 파일 없음
        "//conditions:default": [],
        # "//conditions:default": ["envoy_quic_crypto_server_stream.h"],
    }),
    tags = ["nofips"],
    visibility = [
        "//source/common/quic:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = select({
        "@envoy//bazel:boringssl_fips": [],  # FIPS 모드에서는 의존성 없음
        "//conditions:default": [],
        # "//conditions:default": [
        #     "//envoy/registry",
        #     "//source/common/quic:envoy_quic_server_crypto_stream_factory_lib",
        #     "@envoy_api//envoy/extensions/quic/crypto_stream/v3:pkg_cc_proto",
        # ],
    }),
    alwayslink = LEGACY_ALWAYSLINK,
)

# 나머지 타겟들도 비슷한 방식으로 수정
envoy_cc_extension(
    name = "envoy_quic_default_crypto_server_stream",
    extra_visibility = [
        "//source/common/quic:__subpackages__",
        "//test:__subpackages__",
    ],
    tags = ["nofips"],
    deps = select({
        "@envoy//bazel:boringssl_fips": [],
        "//bazel:boringssl_disabled": [],
        "//conditions:default": [],
        # "//bazel:boringssl_disabled": [],
        # "//conditions:default": [":envoy_quic_crypto_server_stream_lib"],
    }),
)

envoy_cc_library(
    name = "envoy_quic_crypto_client_stream_lib",
    srcs = select({
        "@envoy//bazel:boringssl_fips": [],
        "//conditions:default": [],
        # "//conditions:default": ["envoy_quic_crypto_client_stream.cc"],
    }),
    hdrs = select({
        "@envoy//bazel:boringssl_fips": [],
        "//conditions:default": [],
        # "//conditions:default": ["envoy_quic_crypto_client_stream.h"],
    }),
    tags = ["nofips"],
    visibility = [
        "//source/common/quic:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = select({
        "@envoy//bazel:boringssl_fips": [],
        "//conditions:default": [],
        # "//conditions:default": ["//source/common/quic:envoy_quic_client_crypto_stream_factory_lib"],
    }),
    alwayslink = LEGACY_ALWAYSLINK,
)