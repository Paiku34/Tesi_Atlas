# =============================================================================
# Toolchain CMake: ARM Cortex-M4 (ARMv7-M, Thumb-2)
# Esempio: STM32F407, STM32F429, STM32L4xx
# =============================================================================
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_OBJDUMP arm-none-eabi-objdump)
set(CMAKE_SIZE    arm-none-eabi-size)

# Flag CPU: Cortex-M4 con FPU single-precision
#   M0/M0+: -mcpu=cortex-m0plus -mfloat-abi=soft
#   M3:     -mcpu=cortex-m3     -mfloat-abi=soft
#   M4 SP:  -mcpu=cortex-m4     -mfloat-abi=hard -mfpu=fpv4-sp-d16
#   M7 DP:  -mcpu=cortex-m7     -mfloat-abi=hard -mfpu=fpv5-d16
set(CPU_FLAGS "-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16")

set(CMAKE_C_FLAGS_INIT   "${CPU_FLAGS} -ffunction-sections -fdata-sections -fno-common")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections -specs=nano.specs -lc")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
