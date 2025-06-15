#include <stdio.h>
#include <assert.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/fs_interface.h>
#include "drivers/homo_fs.h"

extern const unsigned char homo_fs_data_start[];
extern const unsigned char homo_fs_data_end[];
extern const unsigned char homo_fs_data_size[];

static struct homo_fs_filesystem_param fs_param;

static struct homo_fs_backend_param fs_backend_params = {
	.base_addr = homo_fs_data_start,
	.size = (int32_t)homo_fs_data_size
};


static struct fs_mount_t mp = {
	.type = FS_TYPE_EXTERNAL_BASE,
	.storage_dev = &fs_backend_params,
	.fs_data = &fs_param,
	.flags = 0,
  .mnt_point = "/abc",
};

static int lsdir(const char *path)
{
	int res;
	struct fs_dir_t dirp;
	static struct fs_dirent entry;
  struct fs_file_t filep = {0};
  char buffer[1024];

	fs_dir_t_init(&dirp);

	/* Verify fs_opendir() */
	res = fs_opendir(&dirp, path);
	if (res) {
		printf("Error opening dir %s [%d]\n", path, res);
		return res;
	}

	printf("\nListing dir %s ...\n", path);
	for (;;) {
		/* Verify fs_readdir() */
		res = fs_readdir(&dirp, &entry);

		/* entry.name[0] == 0 means end-of-dir */
		if (res || entry.name[0] == 0) {
			if (res < 0) {
				printf("Error reading dir [%d]\n", res);
			}
			break;
		}

    assert(fs_open(&filep, "/abc/index.html", FS_O_READ) == 0);

    assert(fs_read(&filep, buffer, sizeof(buffer)) >= 0);

    printf("%s\n", buffer);


		if (entry.type == FS_DIR_ENTRY_DIR) {
			printf("[DIR ] %s\n", entry.name);
		} else {
			printf("[FILE] %s (size = %zu)\n",
				   entry.name, entry.size);
		}
	}

	/* Verify fs_closedir() */
	fs_closedir(&dirp);

	return res;
}


void main(void)
{
    printf("homo start %x\n", homo_fs_data_start);
	  printf("homo magic %x", *(uint32_t*)homo_fs_data_start);
    printf("homo size %x\n", homo_fs_data_size);   
    if (fs_mount(&mp) < 0)
    {
        perror("mount failure !!!");
        return;
    }
    printf("mount success!!");
    lsdir("/abc/");
}