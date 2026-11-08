# =============================================================================
#  CMakeLists.txt — Sonobuoy Crypto Benchmark (Bare-Metal ARM)
#  Porting da Linux/x86 a Cortex-M / Cortex-A bare-metal
#  Compilazione: cmake -DCMAKE_TOOLCHAIN_FILE=toolchain-arm-none-eabi-m4.cmake ..
# =============================================================================
cmake_minimum_required(VERSION 3.10)
project(SonobuoyCryptoBench_BareMetal C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -Wall -Wextra -Wno-unused-parameter")

# =============================================================================
# CONFIGURAZIONE TARGET (da adattare al tuo hardware)
# =============================================================================
if(NOT DEFINED TARGET_CLOCK_HZ)
    set(TARGET_CLOCK_HZ 168000000)
    message(STATUS "TARGET_CLOCK_HZ non definito, default: ${TARGET_CLOCK_HZ} Hz")
endif()
add_definitions(-DCLOCK_HZ=${TARGET_CLOCK_HZ})

if(NOT DEFINED UART_BAUD)
    set(UART_BAUD 115200)
endif()
add_definitions(-DUART_BAUD=${UART_BAUD})

# =============================================================================
# 1. ASCON-C (Stand-Alone, variante bare-metal)
# =============================================================================
if(NOT DEFINED ASCON_VARIANT)
    set(ASCON_VARIANT "opt32")
    message(STATUS "ASCON_VARIANT non definito, default: ${ASCON_VARIANT}")
endif()

set(ASCON_BASE "${CMAKE_CURRENT_SOURCE_DIR}/../src/ascon-c")
set(ASCON_DIR  "${ASCON_BASE}/crypto_aead/asconaead128/${ASCON_VARIANT}")
set(ASCON_TESTS_DIR "${ASCON_BASE}/tests")

if(NOT EXISTS "${ASCON_DIR}/aead.c")
    message(WARNING "Variante ascon-c '${ASCON_VARIANT}' non trovata in ${ASCON_DIR}")
endif()

set(ASCON_SRCS ${ASCON_DIR}/aead.c ${ASCON_DIR}/permutations.c)
if(EXISTS "${ASCON_DIR}/printstate.c")
    list(APPEND ASCON_SRCS ${ASCON_DIR}/printstate.c)
endif()

# =============================================================================
# 2. MBED TLS (compilazione statica — sostituisce OpenSSL + Libsodium)
# =============================================================================
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls")
endif()

set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls_config.h")

if(EXISTS "${MBEDTLS_DIR}/library")
    file(GLOB MBEDTLS_SRCS "${MBEDTLS_DIR}/library/*.c")
    message(STATUS "mbed TLS trovata in: ${MBEDTLS_DIR}")
else()
    set(MBEDTLS_SRCS "")
    message(WARNING "mbed TLS NON trovata. Clona con: git clone https://github.com/Mbed-TLS/mbedtls.git ${MBEDTLS_DIR}")
endif()

# =============================================================================
# 3. ML-KEM REFERENCE C (opzionale — sostituisce liboqs)
# =============================================================================
if(NOT DEFINED MLKEM_DIR)
    set(MLKEM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/mlkem-c-ref")
endif()

if(EXISTS "${MLKEM_DIR}/kem.c")
    set(MLKEM_SRCS
        ${MLKEM_DIR}/kem.c      ${MLKEM_DIR}/indcpa.c
        ${MLKEM_DIR}/poly.c     ${MLKEM_DIR}/polyvec.c
        ${MLKEM_DIR}/ntt.c      ${MLKEM_DIR}/cbd.c
        ${MLKEM_DIR}/reduce.c   ${MLKEM_DIR}/verify.c
        ${MLKEM_DIR}/symmetric-shake.c
    )
    set(HAS_MLKEM TRUE)
    add_definitions(-DHAS_MLKEM=1)
    message(STATUS "ML-KEM reference C trovata in: ${MLKEM_DIR}")
else()
    set(MLKEM_SRCS "")
    set(HAS_MLKEM FALSE)
    message(STATUS "ML-KEM non presente (opzionale)")
endif()

# =============================================================================
# SORGENTI BASE COMUNI (HAL, UART, Core benchmark, RNG)
# =============================================================================
set(COMMON_SRCS
    src/bench_core.c
    src/hal/hal_cortexm.c
    src/hal/hal_cortexa.c
    src/uart_retarget.c
    src/rng_seed.c
)

if(NOT DEFINED LINKER_SCRIPT)
    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/linker/cortexm4_example.ld")
endif()

# Macro helper per configurare ciascun eseguibile (.elf, .bin, .hex, size report)
function(add_embedded_benchmark TARGET_NAME MAIN_SRC EXTRA_SRCS EXTRA_DEFS)
    add_executable(${TARGET_NAME} ${MAIN_SRC} ${COMMON_SRCS} ${EXTRA_SRCS})
    
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${ASCON_DIR}
        ${ASCON_TESTS_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/config
    )
    
    if(EXISTS "${MBEDTLS_DIR}/include")
        target_include_directories(${TARGET_NAME} PRIVATE ${MBEDTLS_DIR}/include)
    endif()

    target_compile_definitions(${TARGET_NAME} PRIVATE
        MBEDTLS_CONFIG_FILE="${MBEDTLS_CONFIG_FILE}"
        ${EXTRA_DEFS}
    )

    set_target_properties(${TARGET_NAME} PROPERTIES
        LINK_FLAGS "-T\"${LINKER_SCRIPT}\" -Wl,--gc-sections -Wl,-Map=${TARGET_NAME}.map"
    )

    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${TARGET_NAME}> ${TARGET_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:${TARGET_NAME}> ${TARGET_NAME}.hex
        COMMAND ${CMAKE_SIZE}    $<TARGET_FILE:${TARGET_NAME}>
        COMMENT "Report dimensioni e file .bin/.hex per ${TARGET_NAME}"
    )
endfunction()

# =============================================================================
# 1. ESEGUIBILE: bench_ascon (Stand-alone ascon-c, NO mbedtls)
# =============================================================================
add_embedded_benchmark(bench_ascon
    src/main_ascon.c
    "src/bench_aead.c;${ASCON_SRCS}"
    ""
)

# =============================================================================
# 2. ESEGUIBILE: bench_mbedtls_aead (AES-256-GCM + ChaCha20-Poly1305)
# =============================================================================
add_embedded_benchmark(bench_mbedtls_aead
    src/main_mbedtls_aead.c
    "src/bench_aead.c;${ASCON_SRCS};${MBEDTLS_SRCS}"
    "HAS_MBEDTLS=1"
)

# =============================================================================
# 3. ESEGUIBILE: bench_key_management (PSK-KDF + Handshake 2-way + X25519)
# =============================================================================
add_embedded_benchmark(bench_key_management
    src/main_key_management.c
    "src/bench_key_management.c;${MBEDTLS_SRCS}"
    "HAS_MBEDTLS=1"
)
