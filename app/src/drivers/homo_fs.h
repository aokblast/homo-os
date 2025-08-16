//
// Created by aokblast on 2025/6/8.
//

#ifndef HOMO_OS_FS_H
#define HOMO_OS_FS_H

#include "homofs.h"
#include <stddef.h>

struct homo_fs_backend_param {
  void *base_addr;
  int size;
  const char *keys;
  const char *ivs;
};

struct homo_fs_filesystem_param {
  struct homo_fs *fs;
};

struct homo_fs_file_param {
  int offset;
  struct homo_fs_file_entry *fent;
};

#endif // HOMO_OS_FS_H
