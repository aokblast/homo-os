//
// Created by aokblast on 2025/6/9.
//
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>

char *strdup(const char *);

#include "queue.h"

#include "homofs.h"
#include "homofs_data.h"

struct homo_fs_file_entry {
  enum FILE_TYPE type;
  const char *name;
  union {
    struct {
      void *buffer;
      uint32_t size;
    } file_data;
    struct {
      LIST_HEAD(, homo_fs_file_entry) children;
    } dir_data;
  };
  LIST_ENTRY(homo_fs_file_entry) siblings;
};

struct homo_fs {
  struct homo_fs_file_entry *root;
};

static struct homo_fs_file_entry *create_dir_node(const char *name) {
  struct homo_fs_file_entry *res = calloc(1, sizeof(struct homo_fs_file_entry));
  if (res == NULL)
    return NULL;
  LIST_INIT(&res->dir_data.children);
  res->type = FS_DIR;
  res->name = strdup(name);
  LIST_INIT(&res->dir_data.children);
  return res;
}

static struct homo_fs_file_entry *create_file_node(const char *name) {
  struct homo_fs_file_entry *res = calloc(1, sizeof(struct homo_fs_file_entry));
  if (res == NULL)
    return NULL;
  res->type = FS_FILE;
  res->name = strdup(name);
  res->file_data.buffer = NULL;
  res->file_data.size = 0;
  return res;
}

static void release_file_entry(struct homo_fs_file_entry *f_entry) {
  struct homo_fs_file_entry *cur, *tmp;
  switch (f_entry->type) {
  case FS_DIR:
    LIST_FOREACH_SAFE(cur, &f_entry->dir_data.children, siblings, tmp) {
      LIST_REMOVE(cur, siblings);
      release_file_entry(cur);
    }
    break;
  case FS_FILE:
    free(f_entry->file_data.buffer);
    break;
  }
  free((void *)f_entry->name);
  free(f_entry);
}

static struct homo_fs_file_entry *find_dir(struct homo_fs_file_entry *root,
                                           char *path,
                                           uint32_t create_while_not_found) {
  const char delimiter[] = "/";
  struct homo_fs_file_entry *cur, *temp;
  struct homo_fs_file_entry *next;
  char *token = strtok(path, delimiter);

  while (token != NULL) {
    next = NULL;

    LIST_FOREACH_SAFE(cur, &root->dir_data.children, siblings, temp) {
      if (strcmp(cur->name, token) != 0)
        continue;
      if (cur->type != FS_DIR)
        return NULL;
      next = cur;
      break;
    }

    if (next == NULL) {
      if (!create_while_not_found)
        return NULL;
      next = create_dir_node(token);
      if (next == NULL)
        return NULL;
      LIST_INSERT_HEAD(&root->dir_data.children, next, siblings);
    }

    root = next;
    token = strtok(NULL, delimiter);
  }

  return root;
}

int homo_fs_init(struct homo_fs **fs) {
  struct homo_fs *tmp;
  if (fs == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp = calloc(1, sizeof(struct homo_fs));
  if (tmp == NULL) {
    errno = ENOMEM;
    return -1;
  }

  tmp->root = create_dir_node("/");
  if (tmp->root == NULL) {
    free(tmp);
    errno = ENOMEM;
    return -1;
  }

  *fs = tmp;
  return 0;
}

static struct homo_fs_file_entry *
extract_dir(struct homo_fs *fs, const char **_path, int create_when_not_found) {
  char *path;
  char *filename;

  if (_path == NULL)
    return NULL;

  path = strdup(*_path);
  if (path == NULL)
    return NULL;

  filename = strrchr(path, '/');
  if (filename == NULL) {
    free(path);
    return NULL;
  }

  *filename = '\0';
  filename++;
  *_path += (filename - path);
  if (*path == '\0')
    return fs->root;

  struct homo_fs_file_entry *res =
      find_dir(fs->root, path, create_when_not_found);
  free(path);
  return res;
}

struct homo_fs_file_entry *
homo_fs_entry_dir_add_file(struct homo_fs_file_entry *dir, const char *filename,
                           enum FILE_TYPE type) {
  struct homo_fs_file_entry *cur, *file;
  if (dir->type != FS_DIR) {
    errno = EINVAL;
    return NULL;
  }

  LIST_FOREACH(cur, &dir->dir_data.children, siblings) {
    if (strcmp(cur->name, filename) != 0)
      continue;
    errno = EEXIST;
    return NULL;
  }

  switch (type) {
  case FS_DIR:
    file = create_dir_node(filename);
    break;
  case FS_FILE:
    file = create_file_node(filename);
    break;
  default:
    return NULL;
  }

  LIST_INSERT_HEAD(&dir->dir_data.children, file, siblings);

  return file;
}

int homo_fs_entry_dir_delete_file(struct homo_fs_file_entry *dir,
                                  const char *filename) {
  struct homo_fs_file_entry *cur, *tmp;
  if (dir->type != FS_DIR) {
    errno = EINVAL;
    return -1;
  }

  LIST_FOREACH_SAFE(cur, &dir->dir_data.children, siblings, tmp) {
    if (strcmp(cur->name, filename) != 0)
      continue;
    LIST_REMOVE(cur, siblings);
    release_file_entry(cur);
    return 0;
  }

  errno = EINVAL;
  return -1;
}

struct homo_fs_file_entry *
homo_fs_add_file(struct homo_fs *fs, const char *path, enum FILE_TYPE type) {
  const char *filename = path;
  struct homo_fs_file_entry *dir;

  if (filename == NULL) {
    errno = EINVAL;
    return NULL;
  }

  dir = extract_dir(fs, &filename, 1);
  if (dir == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return homo_fs_entry_dir_add_file(dir, filename, type);
}

int homo_fs_delete_file(struct homo_fs *fs, const char *path) {
  struct homo_fs_file_entry *dir;
  const char *filename = path;

  if (filename == NULL)
    return EINVAL;

  dir = extract_dir(fs, &filename, 0);
  if (dir == NULL) {
    return EINVAL;
  }

  return homo_fs_entry_dir_delete_file(dir, filename);
}

struct homo_fs_file_entry *homo_fs_find_file(struct homo_fs *fs,
                                             const char *path) {
  const char *filename = path;
  struct homo_fs_file_entry *dir, *file;

  if (filename == NULL) {
    return NULL;
  }

  dir = extract_dir(fs, &filename, 0);
  if (dir == NULL) {
    return NULL;
  }
  if (*filename == '\0')
    return dir;

  LIST_FOREACH(file, &dir->dir_data.children, siblings) {
    if (strcmp(file->name, filename) != 0)
      continue;
    return file;
  }

  return NULL;
}

int homo_fs_entry_file_write_offset(struct homo_fs_file_entry *entry,
                                    const uint8_t *buffer, uint32_t size,
                                    uint32_t offset) {
  if (entry->type != FS_FILE)
    return EINVAL;

  uint32_t right = offset + size;
  if (entry->file_data.buffer == NULL) {
    entry->file_data.buffer = calloc(1, right);
    entry->file_data.size = right;
  }

  if (right > entry->file_data.size) {
    entry->file_data.buffer = realloc(entry->file_data.buffer, right);
    entry->file_data.size = right;
  }

  if (entry->file_data.buffer == NULL) {
    return ENOMEM;
  }

  memcpy((uint8_t *)entry->file_data.buffer + offset, buffer, size);
  return size;
}

int homo_fs_entry_file_read_offset(struct homo_fs_file_entry *entry,
                                   uint8_t *buffer, uint32_t size,
                                   uint32_t offset) {
  uint32_t right = offset + size;
  uint32_t lim_idx =
      right < entry->file_data.size ? right : entry->file_data.size;

  if (entry->file_data.buffer == NULL)
    return 0;

  memcpy(buffer, (uint8_t *)entry->file_data.buffer + offset, lim_idx - offset);

  return lim_idx - offset;
}

void homo_fs_free(struct homo_fs *fs) {
  release_file_entry(fs->root);
  free(fs);
}

const char *homo_fs_entry_get_name(struct homo_fs_file_entry *entry) {
  return entry->name;
}

static int homo_fs_serialize_work(struct homo_fs_file_entry *root,
                                  struct homo_fs_data *data) {
  int offset;
  int n_children = 0, c_offset = 0, idx = 0;
  struct homo_fs_file_entry *ent;

  switch (root->type) {
  case FS_FILE:
    offset = homo_fs_data_file_allocate(data, root->name);
    if (offset == -1) {
      break;
    }
    homo_fs_data_file_write(data, offset, root->file_data.buffer,
                            root->file_data.size);
    break;
  case FS_DIR:
    LIST_FOREACH(ent, &root->dir_data.children, siblings) { ++n_children; }
    offset = homo_fs_data_allocate_directory(data, root->name, n_children);
    if (offset == -1)
      break;

    LIST_FOREACH(ent, &root->dir_data.children, siblings) {
      c_offset = homo_fs_serialize_work(ent, data);
      if (c_offset == -1) {
        offset = -1;
        break;
      }
      homo_fs_data_dir_add_file(data, offset, idx, c_offset);
      ++idx;
    }
    break;
  default:
    offset = -1;
    break;
  }

  return offset;
}

int homo_fs_deserialize_work(struct homo_fs_data *data,
                             struct homo_fs_data_entry *ent,
                             struct homo_fs_file_entry *pdir) {
  struct homo_fs_file_entry *cur;
  cur =
      homo_fs_entry_dir_add_file(pdir, data->str + ent->name_offset, ent->type);

  if (cur == NULL)
    return -1;

  switch (ent->type) {
  case FS_DIR:
    for (int i = 0; i < ent->d_data.n_children; i++) {
      if (homo_fs_deserialize_work(
              data,
              (struct homo_fs_data_entry *)(data->entry +
                                            ent->d_data.children_offsets[i]),
              cur) == -1)
        return -1;
    }
    break;
  case FS_FILE:
    homo_fs_entry_file_write(cur, data->data + ent->f_data.data_offset,
                             ent->f_data.len);
    break;
  }

  return 0;
}

int homo_fs_serialize(struct homo_fs *fs, int fd) {
  struct homo_fs_data data;
  int err;

  if ((err = homo_fs_data_init(&data)) != 0)
    return err;
  homo_fs_serialize_work(fs->root, &data);
  homo_fs_data_serialize(&data, fd, 0);
  homo_fs_data_release(&data);

  return 0;
}

struct homo_fs *homo_fs_deserialize(uint8_t *buffer, size_t sz) {
  struct homo_fs *fs;
  struct homo_fs_data *data;
  struct homo_fs_file_entry *ent, *child;

  if (homo_fs_init(&fs) != 0)
    return NULL;

  data = homo_fs_data_deserialize(buffer, sz);
  if (data == NULL) {
    return NULL;
  }

  int res = homo_fs_deserialize_work(
      data, (struct homo_fs_data_entry *)data->entry, fs->root);

  ent = fs->root;
  child = ent->dir_data.children.lh_first;

  if (child != NULL) {
    fs->root = child;
    LIST_REMOVE(child, siblings);
    release_file_entry(ent);
  }

  if (res)
    return NULL;

  return fs;
}

struct homo_fs_file_entry *homo_fs_get_root(struct homo_fs *fs) {
  return fs->root;
}
int homo_fs_entry_get_type(struct homo_fs_file_entry *ent) { return ent->type; }

int homo_fs_entry_file_get_size(struct homo_fs_file_entry *ent) {
  if (ent->type != FS_FILE)
    return 0;
  return (int)ent->file_data.size;
}

uint8_t *homo_fs_entry_file_get_buffer(struct homo_fs_file_entry *ent) {
  if (ent->type != FS_FILE)
    return NULL;
  return ent->file_data.buffer;
}

int homo_fs_entry_dir_foreach_files(struct homo_fs_file_entry *dir,
                                    homo_fs_dir_entry_cb *callback,
                                    void *user_data) {
  struct homo_fs_file_entry *ent;
  if (dir->type != FS_DIR)
    return 1;

  LIST_FOREACH(ent, &dir->dir_data.children, siblings) {
    if (callback(ent, user_data))
      return 1;
  }

  return 0;
}

struct homo_fs_file_entry *
homo_fs_entry_next_file(struct homo_fs_file_entry *ent) {
  return LIST_NEXT(ent, siblings);
}

struct homo_fs_file_entry *
homo_fs_entry_dir_get_child(struct homo_fs_file_entry *dir) {
  if (dir->type != FS_DIR)
    return NULL;
  return (LIST_FIRST(&dir->dir_data.children));
}
