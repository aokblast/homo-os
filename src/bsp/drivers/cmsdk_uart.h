//
// Created by aokblast on 2025/5/24.
//

#ifndef HOMO_OS_CMSDK_UART_H
#define HOMO_OS_CMSDK_UART_H

int cmsdk_uart_putc(void *addr, char c);
int cmsdk_uart_getc(void *addr);
void cmsdk_uart_init(void *addr);

#endif //HOMO_OS_CMSDK_UART_H
