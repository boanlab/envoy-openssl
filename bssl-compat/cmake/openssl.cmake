find_package(OpenSSL 3.2 COMPONENTS Crypto SSL)

if(OpenSSL_FOUND)
    add_custom_target(OpenSSL)
    get_filename_component(OPENSSL_LIBRARY_DIR ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
    set(OPENSSL_RUNTIME_DIR ${OPENSSL_LIBRARY_DIR} CACHE PATH "OpenSSL runtime library path")
    set(LIBOQS_RUNTIME_DIR ${LIBOQS_INSTALL_DIR}/lib64 CACHE PATH "liboqs runtime library path")
    set(OQSPROV_RUNTIME_DIR ${OPENSSL_INSTALL_DIR}/lib64/ossl-modules CACHE PATH "oqsprovider runtime library path")
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION} (${OPENSSL_LIBRARY_DIR})")
else()
    message(STATUS "Building OpenSSL with OQS provider")
    include(ExternalProject)
    
    # Setup OpenSSL Path
    set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/source)
    set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/install)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_LIBRARY_DIR ${OPENSSL_INSTALL_DIR}/lib64)
    set(LIBOQS_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/liboqs/install)
    set(LIBOQS_INCLUDE_DIR ${LIBOQS_INSTALL_DIR}/include)
    set(OQSPROV_LIBRARY_DIR ${OPENSSL_LIBRARY_DIR}/ossl-modules)

    # OpenSSL 빌드
    ExternalProject_Add(OpenSSL
        URL ${OPENSSL_URL}
        URL_HASH SHA256=${OPENSSL_URL_HASH}
        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config 
            --prefix=${OPENSSL_INSTALL_DIR} 
            --libdir=lib64 
            --openssldir=${OPENSSL_INSTALL_DIR}
            shared        
        BUILD_COMMAND make -j
        TEST_COMMAND ""
        INSTALL_COMMAND make install_sw install_ssldirs
    )

    # liboqs 빌드
    ExternalProject_Add(libOQS
        DEPENDS OpenSSL
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG main
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${LIBOQS_INSTALL_DIR}
            -DCMAKE_BUILD_TYPE=Release
            -DBUILD_SHARED_LIBS=ON
            -DOQS_BUILD_ONLY_LIB=ON
            -DCMAKE_INSTALL_LIBDIR=lib64
#            -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
#            -DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}
#            -DOPENSSL_LIBRARIES=${OPENSSL_LIBRARY_DIR}
        BUILD_COMMAND cmake --build .
        INSTALL_COMMAND cmake --install .
    )

    # 경로 설정
    set(LIBOQS_INCLUDE_DIR "${LIBOQS_INSTALL_DIR}/include" CACHE PATH "liboqs include directory")
    mark_as_advanced(LIBOQS_INCLUDE_DIR)

    # oqsprovider 빌드
    ExternalProject_Add(OQS-Provider
        DEPENDS OpenSSL libOQS
        GIT_REPOSITORY https://github.com/open-quantum-safe/oqs-provider.git
        GIT_TAG 0.7.0
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${OPENSSL_INSTALL_DIR}
            -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
            -Dliboqs_DIR=${LIBOQS_INSTALL_DIR}/lib64/cmake/liboqs
            -DCMAKE_INSTALL_LIBDIR=lib64/ossl-modules
            -DBUILD_SHARED_LIBS=ON
            -DBUILD_TESTING=OFF
            -DCMAKE_SKIP_RPATH=ON
            -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON
        BUILD_COMMAND cmake --build .
        INSTALL_COMMAND cmake --install .
    )

    add_dependencies(libOQS OpenSSL)
    add_dependencies(OQS-Provider libOQS)
endif()

# -DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}
# -DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_LIBRARY_DIR}/libcrypto.so
# -DOPENSSL_SSL_LIBRARY=${OPENSSL_LIBRARY_DIR}/libssl.so

# ${CMAKE_COMMAND} -E env
# OPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
# OPENSSL_LIBRARIES=${OPENSSL_LIBRARY_DIR}
# OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}
