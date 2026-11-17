cmake_minimum_required(VERSION 3.10)
project(RadioTelemetryBenchmark CXX C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -w")

# Percorsi di inclusione interni
include_directories(include)

# Prefisso tesi_env per librerie esterne
if(DEFINED ENV{TESI_ENV})
    set(TESI_PREFIX "$ENV{TESI_ENV}")
elseif(EXISTS "$ENV{HOME}/tesi_env")
    set(TESI_PREFIX "$ENV{HOME}/tesi_env")
else()
    set(TESI_PREFIX "/usr/local")
endif()

# 1. Ascon-C Stand-Alone (opt64 per aarch64 / x86_64)
set(ASCON_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../crypto_benchmarks/src/ascon-c")
set(ASCON_DIR "${ASCON_ROOT}/crypto_aead/asconaead128/opt64")
set(ASCON_SRCS
    ${ASCON_DIR}/aead.c
    ${ASCON_DIR}/permutations.c
    ${ASCON_DIR}/printstate.c
)
include_directories(${ASCON_DIR} ${ASCON_ROOT}/tests)

# 2. Libsodium
find_library(SODIUM_LIB NAMES sodium PATHS ${TESI_PREFIX}/lib ${TESI_PREFIX}/lib64 /usr/lib/aarch64-linux-gnu /usr/local/lib REQUIRED)
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATHS ${TESI_PREFIX}/include /usr/include /usr/local/include REQUIRED)
include_directories(${SODIUM_INCLUDE_DIR})

# 3. OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# 4. Liboqs (Opzionale)
find_library(OQS_LIB NAMES oqs PATHS ${TESI_PREFIX}/lib ${TESI_PREFIX}/lib64 /usr/local/lib /usr/lib)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS ${TESI_PREFIX}/include /usr/local/include /usr/include)
set(OPTIONAL_LIBS "")
if(OQS_LIB AND OQS_INCLUDE_DIR)
    message(STATUS "Trovata liboqs: ${OQS_LIB}")
    include_directories(${OQS_INCLUDE_DIR})
    list(APPEND OPTIONAL_LIBS ${OQS_LIB})
endif()

# Libreria comune radio_telemetry_lib
add_library(radio_telemetry_lib STATIC
    src/serial_port.cpp
    src/crypto_engine.cpp
    ${ASCON_SRCS}
)
target_link_libraries(radio_telemetry_lib PUBLIC
    ${SODIUM_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${OPTIONAL_LIBS}
)

# Eseguibile Boa (Raspberry Pi)
add_executable(buoy_node apps/buoy_node.cpp)
target_link_libraries(buoy_node PRIVATE radio_telemetry_lib)

# Eseguibile Ground Station (Zeno PC)
add_executable(ground_station apps/ground_station.cpp)
target_link_libraries(ground_station PRIVATE radio_telemetry_lib)
