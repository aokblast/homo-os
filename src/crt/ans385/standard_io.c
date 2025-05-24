//
// Created by aokblast on 2025/5/23.
//

#include <stdio.h>
#include "cmsdk_uart.h"

#define UART0_BASE 0x40004000

static int
__uart_putc(char c, FILE *file __unused)
{
	cmsdk_uart_putc((void *)UART0_BASE, c);		/* Defined by underlying system */
  return c;
}

static int
__uart_getc(FILE *file __unused) {
  unsigned char c;
  c = cmsdk_uart_getc((void *)UART0_BASE);
  return c;
}

static FILE __stdin = FDEV_SETUP_STREAM(NULL, __uart_getc, NULL, _FDEV_SETUP_READ);
static FILE __stdout = FDEV_SETUP_STREAM(__uart_putc, NULL, NULL, _FDEV_SETUP_WRITE);

FILE *const stdin = &__stdin;
FILE *const stdout = &__stdout;
__strong_reference(stdout, stderr);

__noreturn void _exit (int status) {
  __builtin_trap();
}

void stdio_init(void)
{
  cmsdk_uart_init((void *)UART0_BASE);
}