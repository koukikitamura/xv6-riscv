#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "user/accounts.h"

static int
account_find(const char *name, uint uid, struct account *account)
{
  int fd;

  fd = open("/passwd", O_RDONLY);
  if (fd < 0)
    return -1;

  while (read(fd, account, sizeof(*account)) == sizeof(*account)) {
    if (account->name[ACCOUNT_NAME - 1] ||
        account->home[sizeof(account->home) - 1] || account->uid > 65535 ||
        account->gid > 65535)
      break;

    int matches;
    if (name != 0)
      matches = strcmp(name, account->name) == 0;
    else
      matches = uid == account->uid;

    if (matches) {
      close(fd);
      return 0;
    }
  }

  close(fd);
  return -1;
}

int
account_name(const char *name, struct account *account)
{
  return account_find(name, 0, account);
}

int
account_uid(uint uid, struct account *account)
{
  return account_find(0, uid, account);
}

static int
group_find(const char *name, uint gid, struct group *group)
{
  int fd;

  fd = open("/group", O_RDONLY);
  if (fd < 0)
    return -1;

  while (read(fd, group, sizeof(*group)) == sizeof(*group)) {
    if (group->name[ACCOUNT_NAME - 1] || group->gid > 65535)
      break;

    int matches;
    if (name != 0)
      matches = strcmp(name, group->name) == 0;
    else
      matches = gid == group->gid;

    if (matches) {
      close(fd);
      return 0;
    }
  }

  close(fd);
  return -1;
}

int
group_name(const char *name, struct group *group)
{
  return group_find(name, 0, group);
}

int
group_gid(uint gid, struct group *group)
{
  return group_find(0, gid, group);
}
