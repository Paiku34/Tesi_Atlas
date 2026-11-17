/* =============================================================================
 * uart_retarget.c — Retarget di printf() / _write() su UART hardware
 *
 * Con arm-none-eabi-gcc + newlib-nano (--specs=nano.specs), printf() chiama
 * _write(). Noi lo reindirizziamo sulla UART del HAL.
 *
 * ORIGINALE (Linux): std::cout / std::ofstream scrivono su stdout/filesystem
 * BARE-METAL:        printf() → _write() → hal_uart_putc() → UART TX → USB → PC
 * =========================================================================== */
#include "hal/hal.h"

/* Funzioni di sistema newlib contrassegnate come weak */
__attribute__((weak)) int _write(int file, char *ptr, int len) {
    (void)file;
    hal_uart_write(ptr, (size_t)len);
    return len;
}

__attribute__((weak)) int _read(int file, char *ptr, int len) {
    (void)file; (void)ptr; (void)len;
    return 0;
}

__attribute__((weak)) int _close(int file) { (void)file; return -1; }

__attribute__((weak)) int _lseek(int file, int offset, int whence) {
    (void)file; (void)offset; (void)whence;
    return 0;
}

__attribute__((weak)) int _isatty(int file) { (void)file; return 1; }

#include <sys/stat.h>
__attribute__((weak)) int _fstat(int file, struct stat *st) {
    (void)file;
    st->st_mode = S_IFCHR;
    return 0;
}

extern char _end;
extern uint32_t _Min_Heap_Size;
static char *heap_ptr = 0;

__attribute__((weak)) void *_sbrk(int incr) {
    extern char _end;
    extern uint32_t _Min_Heap_Size;
    char *prev_heap;

    if (heap_ptr == 0) {
        heap_ptr = &_end;
    }
    prev_heap = heap_ptr;

    /* Controllo overflow heap → stack */
    if ((uint32_t)(heap_ptr + incr) > ((uint32_t)&_end + (uint32_t)&_Min_Heap_Size)) {
        /* Heap esaurito! */
        return (void *)-1;
    }

    heap_ptr += incr;
    return (void *)prev_heap;
}
