//
// Created by aokblast on 2025/6/9.
//

#include "homofs_data.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef HOST_BUILD
#include <time.h>
#endif
#include <unistd.h>

static uint8_t *create_random_hole(uint32_t len) {
  uint8_t *res = malloc(len);
  if (res == NULL)
    return NULL;

  for (int i = 0; i < len; ++i)
    res[i] = rand();

  return res;
}

int homo_fs_data_serialize(homo_fs_data_t *data, int fd, int random_hole) {
  uint8_t *dhole;
  uint32_t dlen;
  uint8_t *shole;
  uint32_t slen;

#ifdef HOST_BUILD
  srand(time(NULL));
#endif
  struct homo_fs_data_header *header = &data->header;
  header->entry_offset = sizeof(struct homo_fs_data_header);
  header->data_offset = header->entry_offset + data->header.entries_size;
  header->str_offset = header->data_offset + data->header.data_size;

  if (random_hole) {
    dlen = rand() % 2000 + 1;
    slen = rand() % 2000 + 1;

    dhole = create_random_hole(dlen);
    if (dhole == NULL) {
      errno = ENOMEM;
      return -1;
    }
    shole = create_random_hole(slen);
    if (shole == NULL) {
      free(dhole);
      errno = ENOMEM;
      return -1;
    }

    data->header.data_offset += dlen;
    data->header.str_offset += slen + dlen;
  }

  write(fd, &data->header, sizeof(data->header));
  write(fd, data->entry, data->header.entries_size);
  if (random_hole)
    write(fd, dhole, dlen);
  write(fd, data->data, data->header.data_size);
  if (random_hole)
    write(fd, shole, slen);
  write(fd, data->str, data->header.str_size);

  if (random_hole) {
    free(dhole);
    free(shole);
  }

  return 0;
}

homo_fs_data_t *homo_fs_data_deserialize(uint8_t *buffer, size_t sz) {
  homo_fs_data_t *data = calloc(1, sizeof(homo_fs_data_t));
  if (data == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  if (sz < sizeof(data->header)) {
    errno = EINVAL;
    return NULL;
  }
  memcpy(&data->header, buffer, sizeof(data->header));
  if (data->header.signature != 0x114514) {
    errno = EINVAL;
    goto failed;
  }

  if (sz < data->header.entry_offset + data->header.entries_size) {
    errno = EINVAL;
    goto failed;
  }
  data->entry = malloc(data->header.entries_size);
  data->entry_caps = data->header.entries_size;
  if (data->entry == NULL) {
    errno = ENOMEM;
    goto failed;
  }
  memcpy(data->entry, buffer + data->header.entry_offset,
         data->header.entries_size);

  if (sz < data->header.data_offset + data->header.data_size)
    goto failed;
  data->data = malloc(data->header.data_size);
  data->data_caps = data->header.data_size;
  if (data->data == NULL)
    goto failed;
  memcpy(data->data, buffer + data->header.data_offset, data->header.data_size);

  if (sz < data->header.str_offset + data->header.str_size) {
    errno = EINVAL;
    goto failed;
  }

  data->str = malloc(data->header.str_size);
  data->str_caps = data->header.str_size;
  if (data->str == NULL) {
    errno = ENOMEM;
    goto failed;
  }
  memcpy(data->str, buffer + data->header.str_offset, data->header.str_size);

  return data;
failed:
  if (data->entry)
    free(data->entry);
  if (data->data)
    free(data->data);
  if (data->str)
    free(data->str);
  free(data);
  return NULL;
}

int homo_fs_data_init(struct homo_fs_data *data) {
#define DEFAULT_CAPS 16
  if (data == NULL) {
    errno = ENOMEM;
    return -1;
  }
  data->header.signature = 0x114514;
  data->header.entries_size = data->header.data_size = data->header.str_size =
      0;

  data->entry_caps = DEFAULT_CAPS;
  data->entry = malloc(data->entry_caps * sizeof(struct homo_fs_data_entry));
  if (data->entry == NULL) {
    errno = ENOMEM;
    return -1;
  }
  data->data_caps = data->str_caps = 1;
  data->str = malloc(data->str_caps);
  if (data->str == NULL) {
    errno = ENOMEM;
    return -1;
  }
  data->data = malloc(data->data_caps);
  if (data->data == NULL) {
    errno = ENOMEM;
    return -1;
  }

  return 0;
}

int homo_fs_data_allocate_directory(homo_fs_data_t *data, const char *dir_name,
                                    int n_children) {
  struct homo_fs_data_header *header = &data->header;
  size_t dir_len = strlen(dir_name) + 1;
  size_t entry_size = sizeof(homo_fs_data_entry_t);
  if (n_children) {
    entry_size += (n_children - 1) * sizeof(uint32_t);
  }

  while (data->entry_caps < (header->entries_size + entry_size)) {
    data->entry_caps *= 2;
    data->entry = realloc(data->entry, data->entry_caps);
  }

  while (data->str_caps < header->str_size + dir_len) {
    data->str_caps *= 2;
    data->str = realloc(data->str, data->str_caps);
  }
  homo_fs_data_entry_t *dir =
      (homo_fs_data_entry_t *)&data->entry[header->entries_size];
  header->entries_size += entry_size;

  dir->type = FS_DIR;
  dir->name_offset = data->header.str_size;
  memcpy(data->str + dir->name_offset, dir_name, dir_len);
  data->header.str_size += dir_len;

  dir->d_data.n_children = n_children;
  return (uint8_t *)dir - data->entry;
}

int homo_fs_data_dir_add_file(homo_fs_data_t *data, int dir_offset, int idx,
                              int file_offset) {
  struct homo_fs_data_header *header = &data->header;
  homo_fs_data_entry_t *dir;

  if (dir_offset >= header->entries_size) {
    errno = EINVAL;
    return -1;
  }

  dir = (homo_fs_data_entry_t *)&data->entry[dir_offset];
  if (dir->d_data.n_children <= idx) {
    errno = EINVAL;
    return -1;
  }

  dir->d_data.children_offsets[idx] = file_offset;
  return 0;
}

int homo_fs_data_file_allocate(homo_fs_data_t *data, const char *f_name) {
  struct homo_fs_data_header *header = &data->header;
  size_t f_len = strlen(f_name) + 1;

  while (data->entry_caps <
         (header->entries_size + sizeof(homo_fs_data_entry_t))) {
    data->entry_caps *= 2;
    data->entry = realloc(data->entry, data->entry_caps);
  }

  while (data->str_caps < (header->str_size + f_len)) {
    data->str_caps *= 2;
    data->str = realloc(data->str, data->str_caps);
  }

  homo_fs_data_entry_t *file =
      (homo_fs_data_entry_t *)&data->entry[header->entries_size];
  header->entries_size += sizeof(homo_fs_data_entry_t);

  file->type = FS_FILE;
  file->name_offset = data->header.str_size;
  memcpy(data->str + file->name_offset, f_name, f_len);
  data->header.str_size += f_len;

  return (uint8_t *)file - data->entry;
}

int homo_fs_data_file_write(homo_fs_data_t *data, int file_offset,
                            uint8_t *buffer, uint32_t size) {
  struct homo_fs_data_header *header = &data->header;
  homo_fs_data_entry_t *file;

  if (file_offset >= header->entries_size) {
    errno = EINVAL;
    return -1;
  }

  while (data->data_caps < (header->data_size + size)) {
    data->data_caps *= 2;
    data->data = realloc(data->data, data->data_caps);
  }

  file = (homo_fs_data_entry_t *)&data->entry[file_offset];
  if (file->type != FS_FILE) {
    errno = EINVAL;
    return -1;
  }

  file->f_data.data_offset = header->data_size;
  file->f_data.len = size;
  memcpy(data->data + header->data_size, buffer, size);
  header->data_size += size;

  return 0;
}

void homo_fs_data_release(struct homo_fs_data *data) {
  if (data->entry)
    free(data->entry);
  if (data->data)
    free(data->data);
  if (data->str)
    free(data->str);
}