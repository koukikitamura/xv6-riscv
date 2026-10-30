#include "kernel/types.h"
#include "user/user.h"
#include "user/accounts.h"

int
main(int argc, char **argv)
{
  struct account owner;
  struct group group;
  int gid;

  if (argc < 3) {
    fprintf(2, "usage: chown user[:group] file...\n");
    exit(1);
  }

  char *colon = strchr(argv[1], ':');
  if (colon)
    *colon++ = 0;

  if (account_name(argv[1], &owner) < 0) {
    fprintf(2, "chown: unknown user or group\n");
    exit(1);
  }

  gid = owner.gid;
  if (colon) {
    if (group_name(colon, &group) < 0) {
      fprintf(2, "chown: unknown user or group\n");
      exit(1);
    }
    gid = group.gid;
  }

  for (int i = 2; i < argc; i++) {
    if (chown(argv[i], owner.uid, gid) < 0) {
      fprintf(2, "chown: cannot change %s\n", argv[i]);
      exit(1);
    }
  }
  exit(0);
}
