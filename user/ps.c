#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/container.h"
#include "user/user.h"

static struct procinfo entries[NPROC];
int
main(void)
{
  static char *states[] = {"unused", "used", "sleep", "ready", "run", "zombie"};
  int n = getprocs(entries, NPROC);
  if (n < 0) {
    fprintf(2, "ps: cannot get processes\n");
    exit(1);
  }
  printf("PID CID STATE NAME\n");
  for (int i = 0; i < n; i++)
    printf("%d %d %s %s\n", entries[i].pid, entries[i].container,
           states[entries[i].state], entries[i].name);
  exit(0);
}
