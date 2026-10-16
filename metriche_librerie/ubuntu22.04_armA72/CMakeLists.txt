cmake_minimum_required(VERSION 3.10)
project(ZenoCryptoBenchmark CXX C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -w")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# --- Gestione Prefisso (se presente variabile d'ambiente o fallback di sistema) ---
if(DEFINED ENV{TESI_ENV})
    set(TESI_PREFIX "$ENV{TESI_ENV}")
elseif(EXISTS "$ENV{HOME}/tesi_env")
    set(TESI_PREFIX "$ENV{HOME}/tesi_env")
else()
    set(TESI_PREFIX "/usr/local")
endif()

# ---------------------------------------------------------
# 1. ASCON (Stand-Alone) - opt64 è 100% compatibile AArch64!
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
find_package(PkgConfig QUIET)
find_library(SODIUM_LIB NAMES sodium PATHS ${TESI_PREFIX}/lib ${TESI_PREFIX}/lib64 /usr/lib/aarch64-linux-gnu /usr/local/lib REQUIRED)
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATHS ${TESI_PREFIX}/include /usr/include /usr/local/include REQUIRED)

add_executable(bench_libsodium src/bench_libsodium.cpp)
target_include_directories(bench_libsodium PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(bench_libsodium PRIVATE ${SODIUM_LIB})

# ---------------------------------------------------------
# 3. OPENSSL (Usa OpenSSL 3.0 nativo del sistema)
# ---------------------------------------------------------
find_package(OpenSSL REQUIRED)
add_executable(bench_openssl src/bench_openssl.cpp)
target_include_directories(bench_openssl PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bench_openssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# ---------------------------------------------------------
# 4. ML-KEM POST-QUANTUM (liboqs)
# ---------------------------------------------------------
find_library(OQS_LIB NAMES oqs PATHS ${TESI_PREFIX}/lib ${TESI_PREFIX}/lib64 /usr/local/lib /usr/lib)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS ${TESI_PREFIX}/include /usr/local/include /usr/include)

if (OQS_LIB AND OQS_INCLUDE_DIR)
    message(STATUS "Trovata liboqs: ${OQS_LIB}")
    add_executable(bench_mlkem src/bench_mlkem.cpp)
    target_include_directories(bench_mlkem PRIVATE ${OQS_INCLUDE_DIR})
    target_link_libraries(bench_mlkem PRIVATE ${OQS_LIB} OpenSSL::Crypto)
else()
    message(WARNING "liboqs non trovata. Esegui la compilazione per abilitare bench_mlkem.")
endif()

# ---------------------------------------------------------
# 5. KEY MANAGEMENT ROADMAP (PSK, Symmetric, ECC X25519)
# ---------------------------------------------------------
add_executable(bench_key_management src/bench_key_management.cpp)
target_include_directories(bench_key_management PRIVATE ${SODIUM_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bench_key_management PRIVATE ${SODIUM_LIB} OpenSSL::Crypto)