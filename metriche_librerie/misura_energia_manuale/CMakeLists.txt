cmake_minimum_required(VERSION 3.10)
project(MisuraEnergiaManuale CXX C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -w")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# ---------------------------------------------------------
# ASCON Sources
# ---------------------------------------------------------
set(ASCON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src/ascon-c/crypto_aead/asconaead128/opt64")
set(ASCON_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src/ascon-c/tests")
set(ASCON_SRCS
    ${ASCON_DIR}/aead.c
    ${ASCON_DIR}/permutations.c
    ${ASCON_DIR}/printstate.c
)

# ---------------------------------------------------------
# DIPENDENZE ESTERNE: Sodium & OpenSSL
# ---------------------------------------------------------
find_library(SODIUM_LIB NAMES sodium REQUIRED)
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATHS /usr/local/include /usr/include /opt/homebrew/include)

find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------
# DIPENDENZA OPZIONALE: liboqs (ML-KEM)
# ---------------------------------------------------------
find_library(OQS_LIB NAMES oqs PATHS /usr/local/lib /usr/lib /opt/homebrew/lib)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS /usr/local/include /usr/include /opt/homebrew/include)

# ---------------------------------------------------------
# 1. Eseguibile AEAD (Ascon, AES, ChaCha)
# ---------------------------------------------------------
add_executable(bench_energia_aead 
    src/bench_energia_aead.cpp 
    ${ASCON_SRCS}
)
target_include_directories(bench_energia_aead PRIVATE 
    ${ASCON_DIR} 
    ${ASCON_TESTS_DIR} 
    ${SODIUM_INCLUDE_DIR} 
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(bench_energia_aead PRIVATE 
    ${SODIUM_LIB} 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# ---------------------------------------------------------
# 2. Eseguibile Key Management (PSK, Handshake, X25519, ML-KEM)
# ---------------------------------------------------------
add_executable(bench_energia_keymgmt 
    src/bench_energia_keymgmt.cpp
)
target_include_directories(bench_energia_keymgmt PRIVATE 
    ${SODIUM_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(bench_energia_keymgmt PRIVATE 
    ${SODIUM_LIB}
    OpenSSL::Crypto
)

if (OQS_LIB AND OQS_INCLUDE_DIR)
    message(STATUS "Trovata liboqs: ${OQS_LIB}. Abilitazione ML-KEM in bench_energia_keymgmt.")
    target_compile_definitions(bench_energia_keymgmt PRIVATE HAVE_LIBOQS=1)
    target_include_directories(bench_energia_keymgmt PRIVATE ${OQS_INCLUDE_DIR})
    target_link_libraries(bench_energia_keymgmt PRIVATE ${OQS_LIB})
else()
    message(WARNING "liboqs non trovata. ML-KEM disabilitato in bench_energia_keymgmt.")
endif()

