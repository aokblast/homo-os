//
// Created by aokblast on 2025/6/14.
//
#define _GNU_SOURCE 1
#include <sys/param.h>
#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "aes.h"

#include "homofs.h"

int f_rev = 0, f_key = 0;
static uint8_t *keys = NULL, *ivs = NULL;

__attribute__((noreturn)) void usage() {
  printf("homo_pack -r -k<key> <dir> <out_file>\n");
  printf("-r unpack\n");
  printf("-k <key> specified key\n");
  exit(1);
}

static int dfs_parse_dir(int fd, struct homo_fs_file_entry *parent, const char *filename) {
  struct stat stat;
  struct stat fs;
  struct homo_fs_file_entry *ent;
  struct dirent *dent;
  struct AES_ctx ctx;
  DIR *d;
  int cfd;
  uint8_t *buffer;

  if (fd == -1) {
    return 1;
  }

  if (fstat(fd, &stat) == -1) {
    return 1;
  }

  if (S_ISDIR(stat.st_mode)) {
    d = fdopendir(fd);
    if (!d) {
      return 1;
    }
    if (filename) {
      ent = homo_fs_entry_dir_add_file(parent, filename, FS_DIR);
      if (ent == NULL)
        return 1;
    } else
      ent = NULL;

    while ((dent = readdir(d)) != NULL) {
      if (0 == strcmp(dent->d_name, ".") || 0 == strcmp(dent->d_name, ".."))
        continue;
      cfd = openat(fd, dent->d_name, O_RDONLY);
      if (dfs_parse_dir(cfd, ent == NULL ? parent : ent, dent->d_name) == 1) {
        close(cfd);
        return 1;
      }
      close(cfd);
    }
    closedir(d);
  } else if (S_ISREG(stat.st_mode)) {
    ent = homo_fs_entry_dir_add_file(parent, filename, FS_FILE);
    if (ent == NULL)
      return 1;

    buffer = malloc(stat.st_size);
    read(fd, buffer, stat.st_size);
    if (keys) {
      AES_init_ctx_iv(&ctx, keys, ivs);
      AES_CBC_encrypt_buffer(&ctx, buffer, stat.st_size - stat.st_size % 16);
    }
    if (homo_fs_entry_file_write(ent, buffer, stat.st_size) != stat.st_size) {
      free(buffer);
      return 1;
    }

    free(buffer);
  } else {
    return 1;
  }

  return 0;
}

static int dfs_parse_fs(struct homo_fs_file_entry *cur, void *user_data) {
  int *pfd = user_data;
  int cfd;
  char file_path[MAXPATHLEN];
  char *buffer;
  int size;
  struct AES_ctx ctx;

  if (homo_fs_entry_get_type(cur) == FS_DIR) {
    cfd = mkdirat(*pfd, homo_fs_entry_get_name(cur), 0700);
    if (cfd == -1 && errno != EEXIST) {
      perror("mkdirat");
      return 1;
    }
    cfd = openat(*pfd, homo_fs_entry_get_name(cur), O_RDONLY);
    if (cfd == -1) {
      perror("openat");
      return 1;
    }

    if (homo_fs_entry_dir_foreach_files(cur, &dfs_parse_fs, &cfd))
      return 1;
  } else {
    cfd = openat(*pfd, homo_fs_entry_get_name(cur), O_CREAT | O_WRONLY);
    if (cfd == -1) {
      perror("openat");
      return 1;
    }
    fchmod(cfd, 0700);
    size = homo_fs_entry_file_get_size(cur);
    buffer = malloc(size);
    memcpy(buffer, homo_fs_entry_file_get_buffer(cur), size);

    if (keys) {
      AES_init_ctx_iv(&ctx, keys, ivs);
      AES_CBC_decrypt_buffer(&ctx, buffer, size - size % 16);
    }
    write(cfd, buffer,size);
    free(buffer);
    close(cfd);
  }

  return 0;
}

static int do_dfs_serialize(int dfd, int ofd, const char *path) {
  struct homo_fs *fs;
  int err;

  homo_fs_init(&fs);

  if (dfs_parse_dir(dfd, homo_fs_get_root(fs), NULL) == 1) {
    printf("Failed to parse\n");
    return 1;
  }
  err = homo_fs_serialize(fs, ofd);
  homo_fs_free(fs);

  return err;
}

static int do_dfs_deserialize(int dfd, int ofd) {
  struct stat stat;
  struct homo_fs *fs;
  uint8_t *buffer;
  int err;

  if (fstat(ofd, &stat) == -1)
    return 1;

  buffer = malloc(stat.st_size);
  if (buffer == NULL)
    return 1;
  read(ofd, buffer, stat.st_size);
  fs = homo_fs_deserialize(buffer, stat.st_size);
  if (fs == NULL)
    return 1;

  err = homo_fs_entry_dir_foreach_files(homo_fs_get_root(fs), &dfs_parse_fs,
                                        &dfd);
  free(buffer);
  homo_fs_free(fs);

  return err;
}

int main(int argc, char *argv[]) {
  int fd, ofd, err = 0;
  int start = 1;
  int c;
  uint8_t ckeys[16] = {0};
  uint8_t civs[16] = {0};

  while((c = getopt(argc, argv, "rk:i:")) != -1) {
      switch (c) {
        case 'r':
          f_rev = 1;
          break;
        case 'k':
          strncpy(ckeys, optarg, sizeof(ckeys));
          keys = ckeys;
          break;
        case 'i':
          strncpy(civs, optarg, sizeof(civs));
          ivs = civs;
        default:
          break;
      }
  }

  if (keys && !ivs)
    ivs = keys;

  start = optind;

  if (!f_rev) {
    fd = open(argv[start], O_RDONLY);
    ofd = open(argv[start + 1], O_RDWR | O_CREAT);
    fchmod(ofd, 0700);
  } else {
    fd = open(argv[start], O_RDONLY);
    if (fd == -1 && errno == ENOENT)
      mkdir(argv[start], 0700);
    fd = open(argv[start], O_RDONLY);
    ofd = open(argv[start + 1], O_RDONLY);
  }

  if (fd == -1 || ofd == -1) {
    perror("open failed: ");
    if (fd != -1)
      close(fd);
    if (ofd != -1)
      close(ofd);
    usage();
  }

  if (!f_rev)
    err = do_dfs_serialize(fd, ofd, argv[start]);
  else
    err = do_dfs_deserialize(fd, ofd);

  close(fd);
  close(ofd);
  return err;
}