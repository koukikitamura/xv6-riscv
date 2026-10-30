#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "kernel/fs.h"
#include "kernel/param.h"
#include "kernel/container.h"
#include "user/user.h"

static struct procinfo procs[NPROC];
static char buffer[1024];

static int
readall(int fd, void *dst, int n)
{
  char *p = dst;

  while (n > 0) {
    int got = read(fd, p, n);
    if (got <= 0)
      return -1;

    p += got;
    n -= got;
  }

  return 0;
}

static uint
little32(uchar *p)
{
  return (uint)p[0] | (uint)p[1] << 8 | (uint)p[2] << 16 | (uint)p[3] << 24;
}

static int
join(char *out, const char *root, const char *name)
{
  if (strlen(root) + strlen(name) + 2 > MAXPATH)
    return -1;

  strcpy(out, root);
  strcpy(out + strlen(out), "/");
  strcpy(out + strlen(out), name);
  return 0;
}

static int
unpack(int fd, char *root)
{
  uchar header[20];
  char path[MAXPATH];
  struct stat st;

  if (readall(fd, header, 12) < 0 || memcmp(header, "XV6IMG1", 8) != 0)
    return -1;

  uint count = little32(header + 8);
  if (count == 0 || count > 64)
    return -1;

  for (uint i = 0; i < count; i++) {
    if (readall(fd, header, sizeof(header)) < 0 || header[14] || header[15])
      return -1;

    char *name = (char *)header;
    if (!name[0] || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strchr(name, '/') || join(path, root, name) < 0 || stat(path, &st) == 0)
      return -1;

    uint size = little32(header + 16);
    if (size > MAXFILE * BSIZE)
      return -1;

    int out = open(path, O_CREATE | O_WRONLY);
    if (out < 0)
      return -1;

    while (size) {
      int n = size > sizeof(buffer) ? sizeof(buffer) : size;
      if (readall(fd, buffer, n) < 0 || write(out, buffer, n) != n) {
        close(out);
        return -1;
      }
      size -= n;
    }

    close(out);
  }

  return read(fd, header, 1) == 0 ? 0 : -1;
}

// Walk using cwd, so even a tree built with many relative chdir calls can
// be removed without a large stack, long paths, or many open descriptors.
static int
remove_tree(char *path)
{
  if (chdir(path) < 0)
    return -1;

  int depth = 0;

  for (;;) {
    struct dirent de;
    struct stat st;
    char name[DIRSIZ + 1];

    int fd = open(".", O_RDONLY);
    if (fd < 0)
      break;

    int found = 0;
    while (read(fd, &de, sizeof(de)) == sizeof(de)) {
      memmove(name, de.name, DIRSIZ);
      name[DIRSIZ] = 0;
      if (de.inum && strcmp(name, ".") && strcmp(name, "..")) {
        found = 1;
        break;
      }
    }
    close(fd);

    if (found) {
      if (unlink(name) == 0)
        continue;

      if (stat(name, &st) < 0 || st.type != T_DIR || chdir(name) < 0)
        break;
      depth++;
    } else {
      if (depth == 0) {
        chdir("/");
        return unlink(path);
      }

      if (chdir("..") < 0)
        break;
      depth--;
    }
  }

  chdir("/");
  return -1;
}

static void
number(char *out, uint n)
{
  char rev[16];
  int i = 0;

  do {
    rev[i++] = '0' + n % 10;
    n /= 10;
  } while (n);

  while (i)
    *out++ = rev[--i];
  *out = 0;
}

static uint64
positive(char *text, int memory)
{
  uint64 n = 0;

  if (*text < '0' || *text > '9')
    return 0;

  while (*text >= '0' && *text <= '9') {
    n = n * 10 + *text++ - '0';
    if (n > 128 * 1024 * 1024)
      return 0;
  }

  if (memory && (*text == 'M' || *text == 'K')) {
    n *= *text++ == 'M' ? 1024 * 1024 : 1024;
  }

  return *text || n > 128 * 1024 * 1024 ? 0 : n;
}

int
main(int argc, char **argv)
{
  char *image = 0;
  char root[MAXPATH];
  struct container_limits limits = {8 * 1024 * 1024, 8, 1};
  int i;

  if (argc < 2 || strcmp(argv[1], "run"))
    goto usage;

  for (i = 2; i < argc && argv[i][0] == '-'; i += 2) {
    if (i + 1 >= argc)
      goto usage;
    if (!strcmp(argv[i], "--image"))
      image = argv[i + 1];
    else if (!strcmp(argv[i], "--cpu"))
      limits.cpus = positive(argv[i + 1], 0);
    else if (!strcmp(argv[i], "--memory"))
      limits.memory = positive(argv[i + 1], 1);
    else if (!strcmp(argv[i], "--max-procs"))
      limits.maxprocs = positive(argv[i + 1], 0);
    else
      goto usage;
  }

  if (!image || i >= argc || !limits.memory || limits.cpus < 1 ||
      limits.cpus > NCPU || limits.maxprocs < 1 || limits.maxprocs > NPROC)
    goto usage;

  // A nested invocation must fail before creating directories.
  int n = getprocs(procs, NPROC);
  if (n < 0)
    exit(1);

  for (int j = 0; j < n; j++) {
    if (procs[j].pid == getpid() && procs[j].container) {
      fprintf(2, "container: nested containers are not supported\n");
      exit(1);
    }
  }

  int fd = open(image, O_RDONLY);
  if (fd < 0) {
    fprintf(2, "container: cannot open image %s\n", image);
    exit(1);
  }

  // Never reuse a previous instance, even after a reboot with reused PIDs.
  int created = 0;
  for (int attempt = 0; attempt < 100; attempt++) {
    strcpy(root, "/c");
    number(root + 2, getpid());
    strcpy(root + strlen(root), "-");
    number(root + strlen(root), attempt);
    if (mkdir(root) == 0) {
      created = 1;
      break;
    }
  }

  if (!created) {
    close(fd);
    fprintf(2, "container: cannot create root\n");
    exit(1);
  }

  if (unpack(fd, root) < 0) {
    close(fd);
    fprintf(2, "container: invalid image or insufficient disk space\n");
    remove_tree(root);
    exit(1);
  }
  close(fd);

  int pid = fork();
  if (pid == 0) {
    if (containerenter(root, &limits) < 0) {
      fprintf(2, "container: cannot enter container\n");
      exit(1);
    }

    exec(argv[i], &argv[i]);
    fprintf(2, "container: cannot execute %s\n", argv[i]);
    exit(1);
  }

  int status = 1;
  if (pid > 0) {
    wait(&status);

    // The kernel kills remaining members when the first process exits.
    // Wait for init to reap orphaned members before removing their files.
    for (;;) {
      int present = 0;
      n = getprocs(procs, NPROC);
      if (n < 0)
        break;

      for (int j = 0; j < n; j++)
        if (procs[j].container == pid)
          present = 1;

      if (!present)
        break;
      pause(1);
    }
  }

  if (remove_tree(root) < 0)
    fprintf(2, "container: cannot remove %s\n", root);
  exit(status);

usage:
  fprintf(2, "usage: container run --image FILE [--cpu N] [--memory N[M|K]] "
             "[--max-procs N] PROGRAM [ARG...]\n");
  exit(1);
}
