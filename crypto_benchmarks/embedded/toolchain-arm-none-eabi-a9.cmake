# =============================================================================
# Toolchain CMake: ARM Cortex-A9 (ARMv7-A, 32-bit bare-metal)
# Esempio: Xilinx Zynq-7020
# Per A53/A72 AArch64 bare-metal serve aarch64-none-elf-gcc
# =============================================================================
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_OBJDUMP arm-none-eabi-objdump)
set(CMAKE_SIZE    arm-none-eabi-size)

# Flag CPU: Cortex-A9 con NEON
#   A7:  -mcpu=cortex-a7  -mfpu=neon-vfpv4
#   A9:  -mcpu=cortex-a9  -mfpu=neon-vfpv3
#   A15: -mcpu=cortex-a15 -mfpu=neon-vfpv4
set(CPU_FLAGS "-mcpu=cortex-a9 -mfloat-abi=hard -mfpu=neon-vfpv3")

set(CMAKE_C_FLAGS_INIT   "${CPU_FLAGS} -ffunction-sections -fdata-sections -fno-common")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections -specs=nosys.specs -specs=nano.specs -lc -lnosys")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
