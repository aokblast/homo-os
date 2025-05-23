//
// Created by aokblast on 2025/5/23.
//


#include "tx_api.h"
#include <stddef.h>
#include <string.h>

#define HEAP_SIZE 16384

TX_BYTE_POOL byte_pool;

void *malloc(size_t size) {
  void *ptr = NULL;
  if (tx_byte_allocate(&byte_pool, &ptr, size, TX_NO_WAIT) != TX_SUCCESS)
    return NULL;
  return ptr;
}

void free(void *ptr) {
  if (ptr) tx_byte_release(ptr);
}

void *calloc(size_t nmemb, size_t size) {
  void *ptr = malloc(nmemb * size);
  if (ptr) memset(ptr, 0, nmemb * size);
  return ptr;
}

void *realloc(void *ptr, size_t size) {
  void *newptr = malloc(size);
  if (newptr && ptr) {
    memcpy(newptr, ptr, size);
    free(ptr);
  }
  return newptr;
}

void init_memory(void **first_byte) {
  tx_byte_pool_create(&byte_pool, "main byte pool", *first_byte, HEAP_SIZE);
  *first_byte += HEAP_SIZE;
}