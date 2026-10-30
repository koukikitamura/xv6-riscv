#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

static void
check(int ok, const char *what)
{
  if (!ok) {
    printf("securitytests: FAIL %s (uid %d)\n", what, getuid());
    exit(1);
  }
}

static void
reap(void)
{
  int status = -1;
  check(wait(&status) > 0 && status == 0, "child result");
}

static int
child(int uid, int gid)
{
  int pid = fork();
  check(pid >= 0, "fork");
  if (pid == 0)
    check(setidentity(uid, gid) == 0, "setidentity");
  return pid == 0;
}

static void
file(const char *path, int uid, int gid, int mode)
{
  int fd = open(path, O_CREATE | O_WRONLY | O_TRUNC);
  check(fd >= 0 && write(fd, "secret", 6) == 6, "create fixture");
  close(fd);
  check(chown(path, uid, gid) == 0 && chmod(path, mode) == 0,
        "fixture metadata");
}

static void
accesscheck(const char *path, int flags, int allowed)
{
  int fd = open(path, flags);
  check((fd >= 0) == allowed, "open permission");
  if (fd >= 0)
    close(fd);
}

static void
matrix(void)
{
  int modes[] = {0000, 0007, 0070, 0700, 0604, 0640, 0444, 0666};
  int ids[][2] = {{1000, 100}, {1001, 100}, {1002, 200}, {0, 0}};
  file("data", 1000, 100, 0600);
  for (int m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
    check(chmod("data", modes[m]) == 0, "matrix chmod");
    for (int role = 0; role < 4; role++) {
      if (child(ids[role][0], ids[role][1])) {
        int bits = role == 3 ? 7 : (modes[m] >> (6 - role * 3)) & 7;
        accesscheck("data", O_RDONLY, !!(bits & 4));
        accesscheck("data", O_WRONLY, !!(bits & 2));
        accesscheck("data", O_RDWR, (bits & 6) == 6);
        accesscheck("data", O_CREATE | O_RDONLY, !!(bits & 4));
        struct stat st;
        check(stat("data", &st) == 0 && st.uid == 1000 && st.gid == 100 &&
                st.mode == modes[m],
              "stat without file read permission");
        exit(0);
      }
      reap();
    }
  }
  check(unlink("data") == 0, "matrix cleanup");
  printf("securitytests: access matrix passed\n");
}

static void
identity(void)
{
  int rootpid = getpid();
  file("data", 1000, 100, 0600);
  if (child(1000, 100)) {
    check(getuid() == 1000 && getgid() == 100, "identity values");
    check(setidentity(0, 0) == -1 && setidentity(1001, 100) == -1,
          "no identity escalation");
    check(chown("data", 1001, 100) == -1, "owner cannot chown");
    check(chmod("data", 0640) == 0, "owner chmod");
    check(chmod("data", 04777) == -1, "no setuid bits");
    check(chmod("/sh", 0777) == -1, "cannot chmod root executable");
    check(mknod("device", 1, 0) == -1, "no device creation");
    check(kill(rootpid) == -1 && kill(1) == -1, "cannot kill root");
    check(consoleset(1000, 0) == -1, "no terminal reconfiguration");
    accesscheck("/shadow", O_RDONLY, 0);
    accesscheck("/passwd", O_WRONLY, 0);
    check(link("/shadow", "stolen") == -1, "no hard links to others' files");
    int pid = fork();
    check(pid >= 0, "identity fork");
    if (pid == 0) {
      char *av[] = {"securitytests", "identity", 0};
      exec("/securitytests", av);
      exit(1);
    }
    reap();
    pid = fork();
    check(pid >= 0, "same-user kill fork");
    if (pid == 0) {
      for (;;)
        pause(10);
    }
    check(kill(pid) == 0, "same-user kill allowed");
    int status;
    check(wait(&status) == pid && status == -1, "killed child status");
    exit(0);
  }
  reap();
  check(setidentity(-1, 0) == -1 && setidentity(0, 65536) == -1, "ID bounds");
  check(chown("data", -1, 0) == -1, "chown bounds");
  unlink("data");
  printf("securitytests: identity passed\n");
}

static void
directories(void)
{
  check(mkdir("dir") == 0, "mkdir fixture");
  file("dir/data", 1000, 100, 0666);
  file("source", 1000, 100, 0600);
  check(chown("dir", 1000, 100) == 0, "dir ownership");
  check(chmod("dir", 0400) == 0, "read-only directory");
  if (child(1000, 100)) {
    accesscheck("dir", O_RDONLY, 1);
    accesscheck("dir/data", O_RDONLY, 0);
    check(chdir("dir") == -1, "chdir requires search");
    check(stat("dir/data", &(struct stat){0}) == -1, "stat requires search");
    exit(0);
  }
  reap();
  chmod("dir", 0100);
  if (child(1000, 100)) {
    accesscheck("dir", O_RDONLY, 0);
    accesscheck("dir/data", O_RDONLY, 1);
    check(chdir("dir") == 0, "execute-only chdir");
    accesscheck("new", O_CREATE | O_WRONLY, 0);
    check(unlink("data") == -1, "unlink requires parent write");
    check(mkdir("newdir") == -1, "mkdir requires parent write");
    check(link("../source", "hard") == -1, "link requires parent write");
    exit(0);
  }
  reap();
  chmod("dir", 0200);
  if (child(1000, 100)) {
    accesscheck("dir/new", O_CREATE | O_WRONLY, 0);
    check(unlink("dir/data") == -1, "write alone cannot unlink");
    exit(0);
  }
  reap();
  chmod("dir", 0300);
  chmod("dir/data", 0000);
  if (child(1000, 100)) {
    check(unlink("dir/data") == 0, "unlink depends on parent, not file");
    check(mkdir("dir/newdir") == 0, "mkdir with write and search");
    check(link("source", "dir/hard") == 0, "owner hard link");
    struct stat st;
    check(stat("dir/newdir", &st) == 0 && st.uid == 1000 && st.gid == 100 &&
            st.mode == 0755,
          "new directory metadata");
    accesscheck("dir/newdir", O_CREATE | O_WRONLY, 0);
    check(unlink("dir/hard") == 0 && unlink("dir/newdir") == 0, "dir cleanup");
    exit(0);
  }
  reap();
  unlink("dir");
  unlink("source");
  printf("securitytests: directories passed\n");
}

static void
truncation(void)
{
  file("data", 1000, 100, 0600);
  if (child(1001, 100)) {
    accesscheck("data", O_WRONLY | O_TRUNC, 0);
    accesscheck("data", O_CREATE | O_WRONLY | O_TRUNC, 0);
    exit(0);
  }
  reap();
  struct stat st;
  check(stat("data", &st) == 0 && st.size == 6, "denial must not truncate");
  accesscheck("data", O_RDONLY | O_TRUNC, 0);
  accesscheck("data", 3, 0);
  accesscheck("data", 0x400000, 0);
  if (child(1000, 100)) {
    int fd = open("data", O_RDWR);
    check(fd >= 0 && chmod("data", 0) == 0, "open before chmod");
    char c;
    check(read(fd, &c, 1) == 1 && write(fd, "X", 1) == 1,
          "existing fd stays valid");
    accesscheck("data", O_RDONLY, 0);
    close(fd);
    check(chmod("data", 0600) == 0, "restore mode");
    accesscheck("data", O_WRONLY | O_TRUNC, 1);
    exit(0);
  }
  reap();
  check(stat("data", &st) == 0 && st.size == 0, "authorized truncate");
  unlink("data");
  printf("securitytests: truncation and descriptors passed\n");
}

static void
execution(void)
{
  int src = open("/echo", O_RDONLY);
  int dst = open("prog", O_CREATE | O_WRONLY | O_TRUNC);
  check(src >= 0 && dst >= 0, "copy executable");
  char buf[512];
  int n;
  while ((n = read(src, buf, sizeof(buf))) > 0)
    check(write(dst, buf, n) == n, "write executable");
  close(src);
  close(dst);
  chown("prog", 1000, 100);
  chmod("prog", 0100);
  if (child(1000, 100)) {
    accesscheck("prog", O_RDONLY, 0);
    char *av[] = {"prog", "execute-only-ok", 0};
    exec("prog", av);
    exit(1);
  }
  reap();
  if (child(1001, 100)) {
    char *av[] = {"prog", 0};
    check(exec("prog", av) == -1, "other cannot execute");
    exit(0);
  }
  reap();
  chmod("prog", 0600);
  char *av[] = {"prog", 0};
  check(exec("prog", av) == -1, "root requires an execute bit");
  unlink("prog");
  printf("securitytests: execution passed\n");
}

static void
terminal(void)
{
  int ready[2];
  check(pipe(ready) == 0, "terminal pipe");
  check(consoleset(1000, 1) == 0, "terminal owner");
  if (child(1000, 100)) {
    close(ready[0]);
    check(write(ready[1], "r", 1) == 1, "terminal ready");
    close(ready[1]);
    char c;
    check(read(0, &c, 1) == -1, "old session loses blocked read");
    exit(0);
  }
  close(ready[1]);
  char c;
  check(read(ready[0], &c, 1) == 1, "terminal handshake");
  close(ready[0]);
  pause(2);
  check(consoleset(1001, 1) == 0, "terminal transfer");
  reap();
  if (child(1000, 100)) {
    check(read(0, &c, 1) == -1, "old session cannot start reading");
    exit(0);
  }
  reap();
  check(consoleset(0, 1) == 0, "restore terminal");
  printf("securitytests: terminal ownership passed\n");
}

int
main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "identity") == 0) {
    check(getuid() == 1000 && getgid() == 100, "fork/exec preserves identity");
    check(setidentity(0, 0) == -1, "exec cannot regain root");
    exit(0);
  }
  check(getuid() == 0, "run tests as root");
  struct stat home;
  check(stat("/alice", &home) == 0 && home.nlink == 1, "mkfs directory links");
  check(stat((char *)~0L, &home) == -1 && stat("/", (void *)~0L) == -1,
        "stat validates user pointers");
  check(chmod((char *)~0L, 0600) == -1 && chown((char *)~0L, 0, 0) == -1,
        "metadata calls validate user pointers");
  check(mkdir("/sectest") == 0, "test directory");
  check(chmod("/sectest", 0777) == 0 && chdir("/sectest") == 0, "test cwd");
  matrix();
  identity();
  directories();
  truncation();
  execution();
  terminal();
  check(chdir("/") == 0 && unlink("/sectest") == 0, "final cleanup");
  printf("ALL SECURITY TESTS PASSED\n");
  exit(0);
}
