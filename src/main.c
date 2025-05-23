//
// Created by aokblast on 2025/5/20.
//
#include "tx_api.h"
#include <stdio.h>
#include <assert.h>

int init_libc(void **first_byte);

#define BYTE_POOL_SIZE     9120
#define STACK_SIZE         1024

TX_THREAD               thread_0;
TX_THREAD               thread_1;
TX_MUTEX                mutex_0;
TX_BYTE_POOL            byte_pool_0;
UCHAR                   memory_area[BYTE_POOL_SIZE];


void    thread_0_entry(ULONG thread_input) {
  UINT    status;

  while(1) {
    status =  tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);
    if (status != TX_SUCCESS)
      break;
    printf("LeminoChen\n");
    status =  tx_mutex_put(&mutex_0);
    if (status != TX_SUCCESS)
      break;
    tx_thread_sleep(2);
  }
}

void    thread_1_entry(ULONG thread_input) {
  UINT    status;

  while(1) {
    status =  tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);
    if (status != TX_SUCCESS)
      break;
    printf("LexChen\n");
    status =  tx_mutex_put(&mutex_0);
    if (status != TX_SUCCESS)
      break;
    tx_thread_sleep(2);
  }
}

int main() {
  tx_kernel_enter();
}

void    tx_application_define(void *first_unused_memory) {
  CHAR    *pointer = TX_NULL;
  assert(init_libc(&first_unused_memory) == 0);
  tx_byte_pool_create(&byte_pool_0, "bp", first_unused_memory, 4096);
  tx_mutex_create(&mutex_0, "mutex 0", TX_NO_INHERIT);
  tx_byte_pool_create(&byte_pool_0, "byte pool 0", memory_area, BYTE_POOL_SIZE);
  tx_byte_allocate(&byte_pool_0, (VOID **) &pointer, STACK_SIZE, TX_NO_WAIT);
  tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                   pointer, STACK_SIZE,
                   1, 1, TX_NO_TIME_SLICE, TX_AUTO_START);
  tx_byte_allocate(&byte_pool_0, (VOID **) &pointer, STACK_SIZE, TX_NO_WAIT);
  tx_thread_create(&thread_1, "thread 1", thread_1_entry, 1,
                   pointer, STACK_SIZE,
                   16, 16, 4, TX_AUTO_START);
  void *d = malloc(1000);
  assert(d);
}