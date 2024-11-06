find_package(OpenSSL 3.2 COMPONENTS Crypto SSL)

if(OpenSSL_FOUND)
    add_custom_target(OpenSSL)
    get_filename_component(OPENSSL_LIBRARY_DIR ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION} (${OPENSSL_LIBRARY_DIR})")
else()
    message(STATUS "Building OpenSSL with OQS provider")
    include(ExternalProject)
    
    # Setup OpenSSL
    set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/source)
    set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/install)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_LIBRARY_DIR ${OPENSSL_INSTALL_DIR}/lib64)

    ExternalProject_Add(libOQS
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG main
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/liboqs/install
            -DCMAKE_BUILD_TYPE=Release
            -DBUILD_SHARED_LIBS=ON
            -DOQS_BUILD_ONLY_LIB=ON
        BUILD_COMMAND cmake --build .
        INSTALL_COMMAND cmake --install .
    )

    # Build OpenSSL
    ExternalProject_Add(OpenSSL
        DEPENDS libOQS
        URL ${OPENSSL_URL}
        URL_HASH SHA256=${OPENSSL_URL_HASH}
        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config 
            --prefix=${OPENSSL_INSTALL_DIR} 
            --libdir=lib64 
            --openssldir=${OPENSSL_INSTALL_DIR}
        BUILD_COMMAND make -j
        TEST_COMMAND ""
        INSTALL_COMMAND make install_sw
    )

    # Build OQS-Provider
#    ExternalProject_Add(OQS-Provider
#        DEPENDS OpenSSL libOQS
#        GIT_REPOSITORY https://github.com/open-quantum-safe/oqs-provider.git
#        GIT_TAG 0.5.2
#        PATCH_COMMAND 
#            # oqsconfig.h 생성
#            COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/include
#            COMMAND ${CMAKE_COMMAND} -E echo "#define OQSPROVIDER_VERSION_TEXT \"0.5.2\"" > <SOURCE_DIR>/include/oqsconfig.h
#            COMMAND ${CMAKE_COMMAND} -E echo "#define OQS_PROVIDER_VERSION_STR \"0.5.2\"" >> <SOURCE_DIR>/include/oqsconfig.h
#            COMMAND ${CMAKE_COMMAND} -E echo "#define OQS_PROVIDER_BUILD_INFO_STR \"OQS Provider v.0.5.2\"" >> <SOURCE_DIR>/include/oqsconfig.h
#            COMMAND ${CMAKE_COMMAND} -E echo "#define OQS_PROVIDER_BASE_BUILD_INFO_STR \"OQS Provider v.0.5.2\"" >> <SOURCE_DIR>/include/oqsconfig.h
#            COMMAND ${CMAKE_COMMAND} -E echo "#define OQS_PROVIDER_COMMIT \"\"" >> <SOURCE_DIR>/include/oqsconfig.h
#            # CMakeLists.txt 재작성
#            COMMAND ${CMAKE_COMMAND} -E echo "cmake_minimum_required(VERSION 3.16)" > <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "project(oqsprovider)" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "find_package(OpenSSL REQUIRED)" >> <SOURCE_DIR>/CMakeLists.txt
#            # 소스 파일 목록
#            COMMAND ${CMAKE_COMMAND} -E echo "set(PROVIDER_SRCS" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqsprov.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_sig.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_kmgmt.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_kem.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqsprov_keys.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_encode_key2any.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_decode_der2key.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqs_endecoder_common.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqsprov_bio.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    oqsprov/oqsprov_capabilities.c" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo ")" >> <SOURCE_DIR>/CMakeLists.txt
#            # 정적 라이브러리 설정
#            COMMAND ${CMAKE_COMMAND} -E echo "add_library(oqsprovider STATIC \${PROVIDER_SRCS})" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "set_target_properties(oqsprovider PROPERTIES POSITION_INDEPENDENT_CODE ON)" >> <SOURCE_DIR>/CMakeLists.txt
#            # 포함 디렉토리와 링크 설정
#            COMMAND ${CMAKE_COMMAND} -E echo "target_include_directories(oqsprovider PRIVATE" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    \${CMAKE_SOURCE_DIR}/include" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    ${CMAKE_CURRENT_BINARY_DIR}/liboqs/install/include" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    ${OPENSSL_INCLUDE_DIR}" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo ")" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "target_link_libraries(oqsprovider PRIVATE" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    ${CMAKE_CURRENT_BINARY_DIR}/liboqs/install/lib/liboqs.a" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    OpenSSL::Crypto" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo ")" >> <SOURCE_DIR>/CMakeLists.txt
#            # 설치 설정
#            COMMAND ${CMAKE_COMMAND} -E echo "install(TARGETS oqsprovider" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    ARCHIVE DESTINATION lib64" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo "    LIBRARY DESTINATION lib64" >> <SOURCE_DIR>/CMakeLists.txt
#            COMMAND ${CMAKE_COMMAND} -E echo ")" >> <SOURCE_DIR>/CMakeLists.txt
#        CMAKE_ARGS
#            -DCMAKE_INSTALL_PREFIX=${OPENSSL_INSTALL_DIR}
#            -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
#            -DBUILD_SHARED_LIBS=OFF
#            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
#        BUILD_COMMAND cmake --build .
#        INSTALL_COMMAND cmake --install .
#    )
    ExternalProject_Add(OQS-Provider
        DEPENDS OpenSSL libOQS
        GIT_REPOSITORY https://github.com/open-quantum-safe/oqs-provider.git
        GIT_TAG 0.5.2
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${OPENSSL_INSTALL_DIR}
            -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
            -Dliboqs_DIR=${CMAKE_CURRENT_BINARY_DIR}/liboqs/install/lib/cmake/liboqs
            -DBUILD_SHARED_LIBS=ON
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${OPENSSL_INSTALL_DIR}/lib
            -DCMAKE_INSTALL_LIBDIR=lib
        BUILD_COMMAND cmake --build .
        INSTALL_COMMAND cmake --install .
    )





    add_dependencies(OpenSSL libOQS)
    add_dependencies(OQS-Provider OpenSSL)
endif()