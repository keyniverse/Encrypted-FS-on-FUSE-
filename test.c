#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
// ... //

char dir_list[256][256];
int curr_dir_idx = -1;

char files_list[256][256];
int curr_file_idx = -1;

char files_content[256][256];
int curr_file_content_idx = -1;

char key_key[32][32];
unsigned char key[32] = {};

AES_KEY enc_key, dec_key;
unsigned char enc_out[256];
unsigned char dec_out[256];

void add_dir(const char *dir_name)
{
	curr_dir_idx++;
	strcpy(dir_list[curr_dir_idx], dir_name);
}

int is_dir(const char *path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
		if (strcmp(path, dir_list[curr_idx]) == 0)
			return 1;

	return 0;
}

void add_file(const char *filename)
{
	curr_file_idx++;
	strcpy(files_list[curr_file_idx], filename);

	curr_file_content_idx++;
	strcpy(files_content[curr_file_content_idx], "");
}

int is_file(const char *path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
		if (strcmp(path, files_list[curr_idx]) == 0)
			return 1;

	return 0;
}

int get_file_index(const char *path)
{
	path++; // Eliminating "/" in the path

	for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
		if (strcmp(path, files_list[curr_idx]) == 0)
			return curr_idx;

	return -1;
}

void write_to_file(const char *path, const char *new_content)
{
	int file_idx = get_file_index(path);

	if (file_idx == -1) // No such file
		return;

    key[31] = file_idx + '0';

	key[0] = file_idx + '0';

	key[10] = file_idx + '0';

	key[20] = file_idx + '0';

	key[30] = file_idx + '0';
    


    strcpy(key_key[file_idx], key);

    printf("Ori_Key: %s\n", key);
	AES_set_encrypt_key(key, 128, &enc_key);
	AES_encrypt(new_content, enc_out, &enc_key);
	strcpy(files_content[file_idx], enc_out);
}

// ... //

static int do_getattr(const char *path, struct stat *st)
{
	st->st_uid = getuid();	   // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid();	   // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time(NULL); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time(NULL); // The last "m"odification of the file/directory is right now

	if (strcmp(path, "/") == 0 || is_dir(path) == 1)
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if (is_file(path) == 1)
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}

	return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	filler(buffer, ".", NULL, 0);  // Current Directory
	filler(buffer, "..", NULL, 0); // Parent Directory

	if (strcmp(path, "/") == 0) // If the user is trying to show the files/directories of the root directory show the following
	{
		for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
			filler(buffer, dir_list[curr_idx], NULL, 0);

		for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
			filler(buffer, files_list[curr_idx], NULL, 0);
	}

	return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int file_idx = get_file_index(path);

	if (file_idx == -1)
		return -1;

	char *content = files_content[file_idx];
    char *key_tmp = key_key[file_idx];      /// Here to -1 for incorrect key

	printf("CONTENT NOT DEC: %s\n", content);
	AES_set_decrypt_key(key_tmp, 128, &dec_key);
	AES_decrypt(content, dec_out, &dec_key);
	memcpy(buffer, dec_out + offset, size);
	return strlen(dec_out) - offset;
}

static int do_mkdir(const char *path, mode_t mode)
{
	path++;
	add_dir(path);

	return 0;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev)
{
	path++;
	add_file(path);

	return 0;
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info)
{
	write_to_file(path, buffer);

	return size;
}
int do_rmdir(const char *path)
{
    path++;
    for (int i = 0; i <= curr_dir_idx; i++)
    {
        if (strcmp(path, dir_list[i]) == 0)
        {

            for (int j = i; j < curr_dir_idx; j++)
            {
                strcpy(dir_list[j], dir_list[j + 1]);
            }
            curr_dir_idx--;
            return 0;
        }
    }
    return -1; 
}

static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,
	.mkdir = do_mkdir,
	.mknod = do_mknod,
	.write = do_write,
	.rmdir = do_rmdir};

int main(int argc, char *argv[])
{
    strncpy((char*)key, argv[1], sizeof(key) - 1);

    int fuse_argc = argc - 1;
    char *fuse_argv[fuse_argc];
    fuse_argv[0] = argv[0];    // program name
    for (int i = 2; i < argc; i++) {
        fuse_argv[i - 1] = argv[i]; // copy mountpoint and remaining FUSE args (e.g., -f)
    }
	return fuse_main(fuse_argc, fuse_argv, &operations, NULL);
}
