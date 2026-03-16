# ── trezor-crypto static library (minimal sources + MSVC stubs) ──────────────

# compiles only the files actually needed + stubs for linker symbols

# referenced by ecdsa.c but never called by our protocol.
set(TREZOR_SOURCES
    ${trezor_crypto_SOURCE_DIR}/bignum.c
    ${trezor_crypto_SOURCE_DIR}/ecdsa.c
    ${trezor_crypto_SOURCE_DIR}/secp256k1.c
    ${trezor_crypto_SOURCE_DIR}/nist256p1.c
    ${trezor_crypto_SOURCE_DIR}/sha2.c
    ${trezor_crypto_SOURCE_DIR}/hmac.c
    ${trezor_crypto_SOURCE_DIR}/memzero.c
    ${trezor_crypto_SOURCE_DIR}/aes/aescrypt.c
    ${trezor_crypto_SOURCE_DIR}/aes/aeskey.c
    ${trezor_crypto_SOURCE_DIR}/aes/aestab.c
    ${trezor_crypto_SOURCE_DIR}/aes/aes_modes.c
    # MSVC replacements
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rand_win.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/trezor_stubs.c
)

add_library(trezor_crypto_lib STATIC ${TREZOR_SOURCES})
target_include_directories(trezor_crypto_lib PUBLIC
    ${trezor_crypto_SOURCE_DIR}
    ${trezor_crypto_SOURCE_DIR}/aes
    ${trezor_crypto_SOURCE_DIR}/ed25519-donna
)

# USE_KECCAK=1 so that HASHER_SHA3K is defined in hasher.h (needed by secp256k1.c)

# not compiling sha3.c/hasher.c — coz only need the enum value.
target_compile_definitions(trezor_crypto_lib PUBLIC
    USE_KECCAK=1
)
if(MSVC)
    target_compile_options(trezor_crypto_lib PRIVATE /W0)
else()
    target_compile_options(trezor_crypto_lib PRIVATE -w)
endif()

# main server exe
add_executable(cot_server
    src/main.cpp
    src/server.cpp
    src/ot_session.cpp
    src/crypto_utils.cpp
    src/proto_utils.cpp
)

target_include_directories(cot_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${trezor_crypto_SOURCE_DIR}
    ${trezor_crypto_SOURCE_DIR}/aes
)

target_compile_definitions(cot_server PRIVATE
    BOOST_ALL_NO_LIB
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(cot_server PRIVATE /W4)
else()
    target_compile_options(cot_server PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(cot_server PRIVATE
    trezor_crypto_lib
)

if(WIN32)
    target_link_libraries(cot_server PRIVATE ws2_32 mswsock bcrypt)
else()
    target_link_libraries(cot_server PRIVATE pthread)
endif()
