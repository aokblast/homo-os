//
// Created by aokblast on 2025/5/23.
//

#include "stdio.h"

#define UART0_BASE 0x4000C000
#define UART_DR    (*(volatile unsigned int*)(UART0_BASE + 0x00))
#define UART_FR    (*(volatile unsigned int*)(UART0_BASE + 0x18))

static int __uart_putc(char c, FILE *file __unused) {
  while (UART_FR & (1 << 5));
  UART_DR = c;
  return c;
}

static int __uart_getc(FILE *file __unused) {
  while (UART_FR & (1 << 4));
  return UART_DR;
}

static FILE __stdin = FDEV_SETUP_STREAM(NULL, __uart_getc, NULL, _FDEV_SETUP_READ);
static FILE __stdout = FDEV_SETUP_STREAM(__uart_putc, NULL, NULL, _FDEV_SETUP_WRITE);

FILE *const stdin = &__stdin;
FILE *const stdout = &__stdout;
__strong_reference(stdout, stderr);

__noreturn void _exit (int status) {
  __builtin_trap();
}