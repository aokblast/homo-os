//
// Created by aokblast on 2025/6/9.
//

#ifndef HOMO_OS_HOMO_FS_H
#define HOMO_OS_HOMO_FS_H

#include "homofs.h"
#include <stdint.h>

#pragma pack(8)

typedef struct homo_fs_data_entry {
  enum FILE_TYPE type;
  uint32_t name_offset;
  union {
    struct {
      uint32_t len;
      uint32_t data_offset;
    } f_data;
    struct {
      uint32_t n_children;
      uint32_t children_offsets[];
    } d_data;
  };
} homo_fs_data_entry_t;

typedef uint8_t *homo_fs_data_data_t;
typedef char *homo_fs_data_str_t;

struct homo_fs_data_header {
  uint32_t signature; // 0x114514
  uint32_t entries_size;
  uint32_t
      entry_offset; // This entry will be filled when serialize and deserialze
  uint32_t data_size;
  uint32_t
      data_offset; // This entry will be filled when serialize and deserialze
  uint32_t str_size;
  uint32_t str_offset;
} __attribute__((packed));

typedef struct homo_fs_data {
  struct homo_fs_data_header header;
  uint8_t *entry;
  uint32_t entry_caps;
  homo_fs_data_data_t data;
  uint32_t data_caps;
  homo_fs_data_str_t str;
  uint32_t str_caps;
} homo_fs_data_t;

int homo_fs_data_serialize(homo_fs_data_t *data, int fd, int random_hole);
homo_fs_data_t *homo_fs_data_deserialize(uint8_t *buffer, size_t sz);
int homo_fs_data_init(struct homo_fs_data *data);
int homo_fs_data_allocate_directory(homo_fs_data_t *data, const char *dir_name,
                                    int n_children);
int homo_fs_data_dir_add_file(homo_fs_data_t *data, int dir_offset, int idx,
                              int file_offset);
int homo_fs_data_file_allocate(homo_fs_data_t *data, const char *f_name);
int homo_fs_data_file_write(homo_fs_data_t *data, int file_offset,
                            uint8_t *buffer, uint32_t size);
void homo_fs_data_release(struct homo_fs_data *data);
#endif // HOMO_OS_HOMO_FS_H
