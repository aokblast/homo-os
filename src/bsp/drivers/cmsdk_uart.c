//
// Created by aokblast on 2025/5/24.
//

#include "stdint.h"
#include "cmsdk_uart.h"

#define UART_DATA      (*(volatile uint32_t *)(addr + 0x00))
#define UART_STATE     (*(volatile uint32_t *)(addr + 0x04))
#define UART_CTRL      (*(volatile uint32_t *)(addr + 0x08))
#define UART_BAUDDIV   (*(volatile uint32_t *)(addr + 0x10))

int cmsdk_uart_putc(void *addr, char c) {
  while (UART_STATE & (1 << 0));
  UART_DATA = c;
}

int cmsdk_uart_getc(void *addr) {
  while (UART_STATE & (1 << 1));
  return UART_DATA &0xFF;
}

void cmsdk_uart_init(void *addr) {
  UART_BAUDDIV = 16;
  UART_CTRL = (1 << 0) | (1 << 1);
}