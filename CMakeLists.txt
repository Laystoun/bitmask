cmake_minimum_required(VERSION 3.22)
project(
    bitmask
    DESCRIPTION "bitmask software"
)
find_package(OpenMP REQUIRED)
add_executable(bitmask
    crypto/kyznechik.cpp
    crypto/utils/key_utils.cpp
    crypto/kyz_cbc.cpp
    crypto/pkcs.cpp
    crypto/SHA256.cpp
    shell/main.cpp
    # The network stack has been temporarily disabled due to
    # the absence of static linking for the npcap network library.
    #[[
    network/arp_spoof.cpp
    network/dns_spoof.cpp
    ]]
    shell/shell.cpp
)
target_compile_options(bitmask PRIVATE
    -O3
)

#[[
target_compile_definitions(bitmask PRIVATE
    KYZ_DEBUG_FINGERPRINT
    KYZ_DEBUG_DESTRUCTOR
)
]]

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(bitmask PRIVATE -mavx2)
endif()
if(WIN32)
    target_compile_options(bitmask PRIVATE -municode)
    target_link_options(bitmask PRIVATE -municode)
endif()

if(MINGW OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_link_options(bitmask PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
endif()

set_target_properties(bitmask PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build"
)
target_include_directories(bitmask PRIVATE
    "${CMAKE_SOURCE_DIR}/Include/sodium/include"
    "${CMAKE_SOURCE_DIR}/Include/npcap/Include"
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/crypto"
    "${CMAKE_SOURCE_DIR}/utils"
    "${CMAKE_SOURCE_DIR}/shell"
    "${CMAKE_SOURCE_DIR}/shell/log"
)
target_link_libraries(bitmask PRIVATE
    OpenMP::OpenMP_CXX
    "${CMAKE_SOURCE_DIR}/Include/sodium/lib/libsodium.a"
    "${CMAKE_SOURCE_DIR}/Include/npcap/Lib/x64/wpcap.lib"
    "${CMAKE_SOURCE_DIR}/Include/npcap/Lib/x64/Packet.lib"
)