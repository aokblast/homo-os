//
// Created by aokblast on 2025/5/23.
//

void init_memory(void **first_byte);
void stdio_init();

int init_libc(void **first_byte) {
  init_memory(first_byte);
  stdio_init();
  return 0;
}