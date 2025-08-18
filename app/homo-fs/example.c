//
// Created by aokblast on 2025/6/15.
//

#include <assert.h>
#include <sys/stat.h>

#include "homofs.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  struct homo_fs *fs;
  struct homo_fs_file_entry *dir, *file;
  struct stat stat;
  uint8_t *data;

  assert(homo_fs_init(&fs) == 0);
  char str[] = "Hello World!\n";

  dir = homo_fs_add_file(fs, "/asngvansvi/sjviansv", FS_DIR);
  assert(dir);
  file = homo_fs_entry_dir_add_file(dir, "114514.c", FS_FILE);
  assert(file);
  assert(homo_fs_entry_file_write(file, (uint8_t *)str, sizeof(str)) ==
         sizeof(str));

  int fd = open("./output", O_WRONLY | O_CREAT);
  assert(fd != -1);
  homo_fs_serialize(fs, fd, 0);
  homo_fs_free(fs);
  close(fd);

  fd = open("./output", O_RDONLY);
  assert(fd != -1);
  assert(fstat(fd, &stat) != -1);
  data = malloc(stat.st_size);
  read(fd, data, stat.st_size);
  fs = homo_fs_deserialize(data, stat.st_size);
  free(data);
  assert(homo_fs_find_file(fs, "/asngvansvi/sjviansv/114514.c") != NULL);
  assert(homo_fs_find_file(fs, "/asngvansvi/sjviansv/114515.c") == NULL);

  file = homo_fs_find_file(fs, "/asngvansvi/sjviansv/114514.c");
  char buffer[255];

  assert(homo_fs_entry_file_read(file, (uint8_t *)buffer, sizeof(buffer)) > 0);
  printf("%s\n", buffer);
  close(fd);
}
