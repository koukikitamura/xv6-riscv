#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char **argv)
{
  int mode = 0;

  if (argc < 3 || strlen(argv[1]) < 3 || strlen(argv[1]) > 4)
    goto usage;

  for (char *p = argv[1]; *p; p++) {
    if (*p < '0' || *p > '7')
      goto usage;
    mode = mode * 8 + *p - '0';
  }

  if (mode > 0777)
    goto usage;

  for (int i = 2; i < argc; i++) {
    if (chmod(argv[i], mode) < 0) {
      fprintf(2, "chmod: cannot change %s\n", argv[i]);
      exit(1);
    }
  }
  exit(0);

usage:
  fprintf(2, "usage: chmod octal-mode file...\n");
  exit(1);
}
