/* =============================================================================
 * Linker Script esempio Cortex-A9 bare-metal (es. Zynq-7020)
 * TEMPLATE — adattare a BSP effettivo.
 * =========================================================================== */
MEMORY
{
    DDR  (rwx) : ORIGIN = 0x00100000, LENGTH = 256M
    OCM  (rwx) : ORIGIN = 0xFFFF0000, LENGTH = 64K
}

_Min_Stack_Size = 0x10000;  /* 64 KB stack */
_Min_Heap_Size  = 0x10000;  /* 64 KB heap  */

ENTRY(_start)

SECTIONS
{
    .text : {
        . = ALIGN(4);
        KEEP(*(.vectors))
        *(.text) *(.text*) *(.rodata) *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > DDR

    .data : AT(_etext) {
        . = ALIGN(4);
        _sdata = .;
        *(.data) *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > DDR

    .bss : {
        . = ALIGN(4);
        _sbss = .;
        __bss_start__ = _sbss;
        *(.bss) *(.bss*) *(COMMON)
        . = ALIGN(4);
        _ebss = .;
        __bss_end__ = _ebss;
    } > DDR

    ._user_heap_stack : {
        . = ALIGN(8);
        PROVIDE(end = .);
        PROVIDE(_end = .);
        . = . + _Min_Heap_Size;
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
    } > DDR

    _estack = ORIGIN(DDR) + LENGTH(DDR);
}
