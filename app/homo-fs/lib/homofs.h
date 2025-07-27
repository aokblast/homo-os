//
// Created by aokblast on 2025/6/9.
//

#ifndef HOMO_OS_HOMOFS_H
#define HOMO_OS_HOMOFS_H

#include <stddef.h>
#include <stdint.h>

enum FILE_TYPE {
  FS_DIR,
  FS_FILE,
};

struct homo_fs;
struct homo_fs_file_entry;
struct homo_fs_data;

/* fs related operation */
int homo_fs_init(struct homo_fs **);
void homo_fs_free(struct homo_fs *);
struct homo_fs_file_entry *homo_fs_add_file(struct homo_fs *, const char *path,
                                            enum FILE_TYPE);
int homo_fs_delete_file(struct homo_fs *, const char *path);
struct homo_fs_file_entry *homo_fs_find_file(struct homo_fs *,
                                             const char *path);
struct homo_fs_file_entry *homo_fs_get_root(struct homo_fs *fs);

/* directory related operation */
typedef int(homo_fs_dir_entry_cb)(struct homo_fs_file_entry *ent,
                                  void *user_data);
struct homo_fs_file_entry *
homo_fs_entry_dir_add_file(struct homo_fs_file_entry *dir, const char *filename,
                           enum FILE_TYPE);
int homo_fs_entry_dir_delete_file(struct homo_fs_file_entry *dir,
                                  const char *filename);
int homo_fs_entry_dir_foreach_files(struct homo_fs_file_entry *dir,
                                    homo_fs_dir_entry_cb *callback,
                                    void *user_data);
struct homo_fs_file_entry *homo_fs_entry_dir_get_child(struct homo_fs_file_entry *dir);

/* file related operation */
int homo_fs_entry_file_write_offset(struct homo_fs_file_entry *,
                                    const uint8_t *buffer, uint32_t size,
                                    uint32_t offset);
#define homo_fs_entry_file_write(_ent, _buffer, _size)                         \
  homo_fs_entry_file_write_offset(_ent, _buffer, _size, 0)
int homo_fs_entry_file_read_offset(struct homo_fs_file_entry *, uint8_t *buffer,
                                   uint32_t size, uint32_t offset);
#define homo_fs_entry_file_read(_ent, _buffer, _size)                          \
  homo_fs_entry_file_read_offset(_ent, _buffer, _size, 0)
const char *homo_fs_entry_get_name(struct homo_fs_file_entry *ent);
int homo_fs_entry_get_type(struct homo_fs_file_entry *ent);
int homo_fs_entry_file_get_size(struct homo_fs_file_entry *ent);
uint8_t *homo_fs_entry_file_get_buffer(struct homo_fs_file_entry *ent);

struct homo_fs_file_entry * homo_fs_entry_next_file(struct homo_fs_file_entry *ent);

/* serialization */
int homo_fs_serialize(struct homo_fs *fs, int fd);
struct homo_fs *homo_fs_deserialize(uint8_t *buffer, size_t sz);

#endif // HOMO_OS_HOMOFS_H
