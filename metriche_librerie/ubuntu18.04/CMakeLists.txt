cmake_minimum_required(VERSION 3.10)
project(ZenoCryptoBenchmark CXX C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -w")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# --- DEFINIZIONE AMBIENTE LOCALE TESI ---
set(TESI_ENV "/home/klaudio/tesi_env")

# ---------------------------------------------------------
# 1. ASCON (Stand-Alone)
# ---------------------------------------------------------
set(ASCON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/ascon-c/crypto_aead/asconaead128/opt64")
set(ASCON_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/ascon-c/tests")

set(ASCON_SRCS
    ${ASCON_DIR}/aead.c
    ${ASCON_DIR}/permutations.c
    ${ASCON_DIR}/printstate.c
)

add_executable(bench_ascon src/bench_ascon.cpp ${ASCON_SRCS})
target_include_directories(bench_ascon PRIVATE ${ASCON_DIR} ${ASCON_TESTS_DIR})

# ---------------------------------------------------------
# 2. LIBSODIUM
# ---------------------------------------------------------
find_library(SODIUM_LIB NAMES sodium PATHS ${TESI_ENV}/lib ${TESI_ENV}/lib64 REQUIRED)
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATHS ${TESI_ENV}/include REQUIRED)
add_executable(bench_aead_libsodium src/bench_aead_libsodium.cpp)
target_include_directories(bench_aead_libsodium PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(bench_aead_libsodium PRIVATE ${SODIUM_LIB})

# ---------------------------------------------------------
# 3. OPENSSL
# ---------------------------------------------------------
set(OPENSSL_ROOT_DIR "${TESI_ENV}")
find_package(OpenSSL REQUIRED)
add_executable(bench_aead_openssl src/bench_aead_openssl.cpp)
target_include_directories(bench_aead_openssl PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bench_aead_openssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# ---------------------------------------------------------
# 4. ML-KEM POST-QUANTUM (liboqs)
# ---------------------------------------------------------
find_library(OQS_LIB NAMES oqs PATHS ${TESI_ENV}/lib ${TESI_ENV}/lib64)
if (OQS_LIB)
    message(STATUS "Trovata liboqs: ${OQS_LIB}")
    add_executable(bench_mlkem src/bench_mlkem.cpp)
    target_include_directories(bench_mlkem PRIVATE ${TESI_ENV}/include)
    target_link_libraries(bench_mlkem PRIVATE ${OQS_LIB} OpenSSL::Crypto)
else()
    message(WARNING "liboqs non trovata in ${TESI_ENV}. Esegui la compilazione di liboqs.")
endif()

# ---------------------------------------------------------
# 5. KEY MANAGEMENT ROADMAP (PSK, Symmetric, ECC X25519)
# ---------------------------------------------------------
add_executable(bench_key_management src/bench_key_management.cpp)
target_include_directories(bench_key_management PRIVATE ${SODIUM_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bench_key_management PRIVATE ${SODIUM_LIB} OpenSSL::Crypto)