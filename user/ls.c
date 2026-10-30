#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "user/accounts.h"

static void
show(char *path, struct stat *st)
{
  char mode[11] = "----------";
  char *bits = "rwx";
  struct account owner;
  struct group group;

  if (st->type == T_DIR)
    mode[0] = 'd';
  else if (st->type == T_DEVICE)
    mode[0] = 'c';

  for (int i = 0; i < 9; i++)
    if (st->mode & (1 << (8 - i)))
      mode[i + 1] = bits[i % 3];

  printf("%s ", mode);

  if (account_uid(st->uid, &owner) == 0)
    printf("%s ", owner.name);
  else
    printf("%d ", st->uid);

  if (group_gid(st->gid, &group) == 0)
    printf("%s ", group.name);
  else
    printf("%d ", st->gid);

  char *name = path;
  for (char *p = path; *p; p++)
    if (*p == '/' && p[1])
      name = p + 1;
  printf("%s\n", name);
}

void
ls(char *path)
{
  char buf[512], *p;
  int fd;
  struct dirent de;
  struct stat st;

  if (stat(path, &st) < 0) {
    fprintf(2, "ls: cannot stat %s\n", path);
    return;
  }
  if (st.type != T_DIR) {
    show(path, &st);
    return;
  }
  if ((fd = open(path, O_RDONLY)) < 0) {
    fprintf(2, "ls: cannot open %s\n", path);
    return;
  }

  switch (st.type) {
  case T_DEVICE:
  case T_FILE:
    show(path, &st);
    break;

  case T_DIR:
    if (strlen(path) + 1 + DIRSIZ + 1 > sizeof buf) {
      printf("ls: path too long\n");
      break;
    }
    strcpy(buf, path);
    p = buf + strlen(buf);
    *p++ = '/';
    while (read(fd, &de, sizeof(de)) == sizeof(de)) {
      if (de.inum == 0)
        continue;
      memmove(p, de.name, DIRSIZ);
      p[DIRSIZ] = 0;
      if (stat(buf, &st) < 0) {
        printf("ls: cannot stat %s\n", buf);
        continue;
      }
      show(buf, &st);
    }
    break;
  }
  close(fd);
}

int
main(int argc, char *argv[])
{
  int i;

  if (argc < 2) {
    ls(".");
    exit(0);
  }
  for (i = 1; i < argc; i++)
    ls(argv[i]);
  exit(0);
}
