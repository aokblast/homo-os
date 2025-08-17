//
// Created by aokblast on 2025/6/8.
//

#include "homo_fs.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/drivers/flash.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/fs_sys.h>
#include <zephyr/fs/zms.h>
#include <zephyr/init.h>
#include <zephyr/storage/flash_map.h>

#include <aes.h>

static int homo_fs_mount(struct fs_mount_t *mount) {
  struct homo_fs_backend_param *backend = mount->storage_dev;
  struct homo_fs_filesystem_param *fs = mount->fs_data;

  if (mount->type != FS_TYPE_EXTERNAL_BASE || backend == NULL)
    return -EINVAL;

  return (fs->fs = homo_fs_deserialize(backend->base_addr, backend->size)) ==
         NULL;
}

static int homo_fs_unmount(struct fs_mount_t *mount) {
  struct homo_fs_filesystem_param *fs = mount->fs_data;
  homo_fs_free(fs->fs);
  return 0;
}

static int homo_fs_open(struct fs_file_t *filp, const char *fs_path,
                        fs_mode_t flags) {
  struct homo_fs_filesystem_param *fs = filp->mp->fs_data;
  struct homo_fs_file_entry *ent;
  struct homo_fs_file_param *file;
  fs_path += filp->mp->mountp_len;
  ent = homo_fs_find_file(fs->fs, fs_path);
  filp->filep = NULL;

  if (ent == NULL)
    return (-ENOENT);

  file = malloc(sizeof(struct homo_fs_file_param));
  file->offset = 0;
  file->fent = ent;
  filp->filep = file;
  return 0;
}

static ssize_t homo_fs_read(struct fs_file_t *filp, void *dest, size_t nbytes) {
  struct homo_fs_file_param *param = filp->filep;
  struct homo_fs_backend_param *backend = filp->mp->storage_dev;
  struct AES_ctx ctx;
  char *buffer;
  int max_size = homo_fs_entry_file_get_size(param->fent);
  int offset = param->offset;

  param->offset += nbytes;
  if (param->offset > max_size)
    param->offset = max_size;

  if (backend->keys) {
    buffer = malloc(max_size);
    homo_fs_entry_file_read(param->fent, (uint8_t *)buffer, max_size);
    AES_init_ctx_iv(&ctx, backend->keys, backend->ivs);
    AES_CBC_decrypt_buffer(&ctx, buffer, max_size - max_size % 16);
    nbytes = MIN(nbytes, max_size - offset);
    memcpy(dest, buffer + offset, MIN(nbytes, max_size - offset));
    free(buffer);
  } else {
    nbytes = homo_fs_entry_file_read_offset(param->fent, (uint8_t *)dest,
                                            nbytes, offset);
  }

  return nbytes;
}

int homo_fs_lseek(struct fs_file_t *filp, off_t off, int whence) {
  struct homo_fs_file_param *param = filp->filep;
  int max_size = homo_fs_entry_file_get_size(param->fent);

  switch (whence) {
  case SEEK_CUR:
    if ((param->offset + off) > max_size || (param->offset + off) < 0)
	    return (-EINVAL);
    param->offset += off;
    break;
  case SEEK_END:
    if ((max_size + off) > max_size || (max_size + off) < 0)
      return -EINVAL;
    param->offset = max_size + off;
    break;
  case SEEK_SET:
    if (off > max_size || off < 0)
      return -EINVAL;
    param->offset = off;
    break;
  default:
    return -EINVAL;
  }

  return 0;
}

off_t homo_fs_tell(struct fs_file_t *filp) {
  return homo_fs_lseek(filp, 0, SEEK_END);
}

int homo_fs_close(struct fs_file_t *filp) {
  struct homo_fs_file_param *param = filp->filep;
  free(param);
  return 0;
}

int homo_fs_opendir(struct fs_dir_t *dirp, const char *fs_path) {
  struct homo_fs_filesystem_param *param = dirp->mp->fs_data;
  struct homo_fs_file_entry *file;
  fs_path += dirp->mp->mountp_len;
  file = homo_fs_find_file(param->fs, fs_path);
  if (file == NULL)
    return -ENOENT;
  dirp->dirp = homo_fs_entry_dir_get_child(file);
  return 0;
}

int homo_fs_readdir(struct fs_dir_t *dirp, struct fs_dirent *entry) {
  struct homo_fs_file_entry *fent = dirp->dirp;

  if (fent == NULL) {
    entry->name[0] = '\0';
    return 0;
  }

  entry->type = homo_fs_entry_get_type(fent) == FS_DIR ? FS_DIR_ENTRY_DIR
                                                       : FS_DIR_ENTRY_FILE;
  entry->size = homo_fs_entry_get_type(fent) == FS_DIR
                    ? 0
                    : homo_fs_entry_file_get_size(fent);
  strncpy(entry->name, homo_fs_entry_get_name(fent), MAX_FILE_NAME);
  dirp->dirp = homo_fs_entry_next_file(fent);
  return 0;
}

int homo_fs_closedir(struct fs_dir_t *dirp __unused) { return 0; }

int homo_fs_stat(struct fs_mount_t *mountp, const char *path,
                 struct fs_dirent *entry) {
  struct homo_fs_filesystem_param *param = mountp->fs_data;
  path += mountp->mountp_len;
  struct homo_fs_file_entry *fent = homo_fs_find_file(param->fs, path);
  if (fent == NULL)
    return -ENOENT;
  entry->type = homo_fs_entry_get_type(fent) == FS_DIR ? FS_DIR_ENTRY_DIR
                                                       : FS_DIR_ENTRY_FILE;
  entry->size = homo_fs_entry_get_type(fent) == FS_DIR
                    ? 0
                    : homo_fs_entry_file_get_size(fent);
  strncpy(entry->name, homo_fs_entry_get_name(fent), MAX_FILE_NAME);

  return 0;
}

static struct fs_file_system_t homo_fs = {
    .mount = homo_fs_mount,
    .unmount = homo_fs_unmount,
    .open = homo_fs_open,
    .read = homo_fs_read,
    .lseek = homo_fs_lseek,
    .tell = homo_fs_tell,
    .close = homo_fs_close,
    .stat = homo_fs_stat,
    .opendir = homo_fs_opendir,
    .readdir = homo_fs_readdir,
    .closedir = homo_fs_closedir,
};

static int register_homo_fs() {
  return fs_register(FS_TYPE_EXTERNAL_BASE, &homo_fs);
}

SYS_INIT(register_homo_fs, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
