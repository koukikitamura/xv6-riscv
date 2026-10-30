#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "kernel/param.h"
#include "kernel/container.h"
#include "kernel/elf.h"
#include "user/user.h"

#define PAGE     4096
#define ROUND(n) (((n) + PAGE - 1) & ~(PAGE - 1))
static struct procinfo infos[NPROC];
static int hostpid;

static void
check(int ok, char *what)
{
  if (!ok) {
    printf("FAIL: %s\n", what);
    exit(1);
  }
}

static void
enter(uint64 memory, int maxprocs)
{
  struct container_limits lim = {memory, maxprocs, 1};
  check(containerenter("/ctest", &lim) > 0, "containerenter");
}

static void
isolation(void)
{
  int external = open("/outside", O_RDONLY);
  check(external >= 0, "open outside before entry");
  close(0);
  check(dup(external) == 0, "external file at stdin");
  enter(8 * 1024 * 1024, 8);
  char byte;
  check(read(0, &byte, 1) < 0, "external stdin closed");
  check(read(external, &byte, 1) < 0, "external descriptors closed");
  check(open("/outside", O_RDONLY) < 0, "absolute path isolated");
  check(chdir("../../../../") == 0, "root parent traversal");
  check(open("outside", O_RDONLY) < 0, "relative path isolated");
  check(open("/../outside", O_RDONLY) < 0, "dotdot isolated");
  check(link("/../outside", "/stolen") < 0, "external hard link denied");
  check(unlink("/../outside") < 0, "external unlink denied");
  check(mknod("/device", 1, 0) < 0, "device creation denied");
  check(open("/device", O_RDWR) < 0, "preexisting device open denied");
  check(kill(hostpid) < 0, "host kill denied");
  struct container_limits lim = {8 * 1024 * 1024, 8, 1};
  check(containerenter("/", &lim) < 0, "nested entry denied");
  int n = getprocs(infos, NPROC);
  check(n == 1 && infos[0].pid == getpid() && infos[0].container == getpid(),
        "process listing isolated");
  check(getprocs((void *)-1, 1) < 0, "invalid getprocs address");
  check(getprocs(infos, NPROC + 1) < 0, "invalid capacity");
  int pid = fork();
  check(pid >= 0, "isolated fork");
  if (pid == 0) {
    check(open("/outside", O_RDONLY) < 0, "fork inherits root");
    check(kill(hostpid) < 0, "fork inherits membership");
    exit(0);
  }
  int status;
  check(wait(&status) == pid && status == 0, "isolated child status");
  char *args[] = {"echo", "PASS: exec in container", 0};
  exec("/echo", args);
  check(0, "exec inside root");
}

static void
memory(void)
{
  uint64 baseline = ROUND((uint64)sbrk(0));
  enter(baseline + 2 * PAGE, 8);
  check(sbrk(2 * PAGE) != SBRK_ERROR, "eager reservation within limit");
  check(sbrk(1) == SBRK_ERROR, "eager limit enforced");
  check(sbrklazy(PAGE) == SBRK_ERROR, "lazy limit enforced");
  check(fork() < 0, "fork memory limit enforced");
  check(sbrk(-2 * PAGE) != SBRK_ERROR, "shrink releases charge");
  char *lazy = sbrklazy(2 * PAGE);
  check(lazy != SBRK_ERROR, "lazy reservation after shrink");
  lazy[0] = 42;
  lazy[PAGE] = 43;
  check(lazy[0] == 42 && lazy[PAGE] == 43,
        "lazy fault allocates reserved pages");
  check(sbrk(-2 * PAGE) != SBRK_ERROR, "lazy shrink releases charge");
  char *args[] = {"big", 0};
  for (int i = 0; i < 4; i++) {
    check(exec("/big", args) < 0, "exec memory limit enforced");
    check(sbrk(2 * PAGE) != SBRK_ERROR, "failed exec rolls back charge");
    check(sbrk(-2 * PAGE) != SBRK_ERROR, "release after failed exec");
  }
}

static void
processes(void)
{
  enter(8 * 1024 * 1024, 2);
  for (int round = 0; round < 4; round++) {
    int pid = fork();
    check(pid >= 0, "process slot available");
    if (pid == 0) {
      pause(2);
      exit(0);
    }
    check(fork() < 0, "process count enforced");
    int status;
    check(wait(&status) == pid && status == 0, "wait releases process slot");
  }
}

static void
aggregate(void)
{
  uint64 baseline = ROUND((uint64)sbrk(0));
  enter(2 * baseline + 3 * PAGE, 3);
  int fd[2];
  check(pipe(fd) == 0, "internal pipe");
  int pid = fork();
  check(pid >= 0, "aggregate fork");
  if (pid == 0) {
    close(fd[0]);
    check(sbrklazy(3 * PAGE) != SBRK_ERROR, "child reserves shared allowance");
    check(write(fd[1], "x", 1) == 1, "signal reserved memory");
    pause(3);
    exit(0);
  }
  close(fd[1]);
  char byte;
  check(read(fd[0], &byte, 1) == 1, "wait for child reservation");
  check(sbrklazy(PAGE) == SBRK_ERROR, "memory shared between processes");
  int status;
  check(wait(&status) == pid && status == 0, "aggregate child status");
  check(sbrklazy(3 * PAGE) != SBRK_ERROR, "reap releases child memory");
  close(fd[0]);
}

static void
lifetime(void)
{
  enter(8 * 1024 * 1024, 8);
  int pid = fork();
  check(pid >= 0, "lifetime fork");
  if (pid == 0)
    for (;;)
      pause(10);
  // Exiting the leader must terminate this child as well.
}

static void
cpu(void)
{
  enter(8 * 1024 * 1024, 8);
  int start = uptime();
  for (int i = 0; i < 3; i++) {
    int pid = fork();
    check(pid >= 0, "cpu worker fork");
    if (pid == 0) {
      while (uptime() - start < 35)
        ;
      exit(0);
    }
  }
  while (wait(0) > 0)
    ;
  int elapsed = uptime() - start;
  int n = getprocs(infos, NPROC);
  check(n == 1, "cpu workers reaped");
  // One tick is 1,000,000 timebase units. Account for period bursts,
  // the initial partial period, and up to one in-flight slice per hart.
  printf("CPU: elapsed=%d ticks runtime=%ld\n", elapsed, infos[0].runtime);
  check(infos[0].runtime > 10000000UL, "cpu workers made progress");
  check(infos[0].runtime < (uint64)elapsed * 1500000UL + 3000000UL,
        "aggregate cpu budget enforced");
}

static void
copyfile(char *from, char *to)
{
  char buf[512];
  int in = open(from, O_RDONLY);
  int out = open(to, O_CREATE | O_WRONLY | O_TRUNC);
  check(in >= 0 && out >= 0, "copy fixture");
  int n;
  while ((n = read(in, buf, sizeof(buf))) > 0)
    check(write(out, buf, n) == n, "write fixture");
  check(n == 0, "read fixture");
  close(in);
  close(out);
}

// Exercise the real archive parser, including paths that would escape the
// extraction directory if copied without validation.
static void
badimages(void)
{
  char *names[] = {"../outside", "/outside", "..", "duplicate", "truncated"};
  for (int i = 0; i < 5; i++) {
    char header[20];
    int fd = open("/badimage", O_CREATE | O_WRONLY | O_TRUNC);
    check(fd >= 0, "bad image fixture");
    memset(header, 0, sizeof(header));
    memmove(header, "XV6IMG1", 8);
    header[8] = i == 3 ? 2 : 1;
    check(write(fd, header, 12) == 12, "image header");
    memset(header, 0, sizeof(header));
    strcpy(header, names[i]);
    if (i == 4)
      header[16] = 1; // Missing one promised byte of content.
    check(write(fd, header, 20) == 20, "image record");
    if (i == 3)
      check(write(fd, header, 20) == 20, "duplicate image record");
    close(fd);
    int pid = fork();
    check(pid >= 0, "image test fork");
    if (pid == 0) {
      char *args[] = {"container", "run", "--image", "/badimage", "/sh", 0};
      exec("/container", args);
      exit(99);
    }
    int status;
    check(wait(&status) == pid && status == 1, "malformed image rejected");
  }
  unlink("/badimage");
  printf("PASS: malformed images\n");
}

static void
run(char *name, void (*fn)(void))
{
  int pid = fork();
  check(pid >= 0, "test fork");
  if (pid == 0) {
    fn();
    exit(0);
  }
  int status;
  check(wait(&status) == pid && status == 0, name);
  for (int tries = 0;; tries++) {
    int n = getprocs(infos, NPROC), found = 0;
    for (int i = 0; i < n; i++)
      found |= infos[i].container == pid;
    if (!found)
      break;
    check(tries < 50, "container members reclaimed");
    pause(1);
  }
  printf("PASS: %s\n", name);
}

int
main(void)
{
  hostpid = getpid();
  mkdir("/ctest");
  int fd = open("/outside", O_CREATE | O_WRONLY | O_TRUNC);
  check(fd >= 0 && write(fd, "host", 4) == 4, "outside fixture");
  close(fd);
  copyfile("/echo", "/ctest/echo");
  mknod("/ctest/device", 1, 0);
  struct elfhdr elf;
  struct proghdr ph;
  memset(&elf, 0, sizeof(elf));
  memset(&ph, 0, sizeof(ph));
  elf.magic = ELF_MAGIC;
  elf.phoff = sizeof(elf);
  elf.phnum = 1;
  ph.type = ELF_PROG_LOAD;
  ph.memsz = 2 * 1024 * 1024;
  ph.flags = 7;
  fd = open("/ctest/big", O_CREATE | O_WRONLY | O_TRUNC);
  check(fd >= 0, "big fixture");
  check(write(fd, &elf, sizeof(elf)) == sizeof(elf), "ELF header");
  check(write(fd, &ph, sizeof(ph)) == sizeof(ph), "program header");
  close(fd);
  struct container_limits bad = {0, 1, 1};
  check(containerenter("/ctest", &bad) < 0, "invalid memory rejected");
  check(containerenter("/outside", &bad) < 0, "file root rejected");
  check(containerenter("/ctest", (void *)-1) < 0, "invalid limits address");
  badimages();
  run("filesystem and process isolation", isolation);
  run("memory and exec rollback", memory);
  run("process limits and reuse", processes);
  run("aggregate memory", aggregate);
  run("leader exit cleanup", lifetime);
  run("CPU quota", cpu);
  for (int i = 0; i < NPROC + 2; i++)
    run("container slot reuse", lifetime);
  fd = open("/outside", O_RDONLY);
  char data[4];
  check(fd >= 0 && read(fd, data, 4) == 4 && !memcmp(data, "host", 4),
        "host file unchanged");
  close(fd);
  unlink("/outside");
  unlink("/ctest/echo");
  unlink("/ctest/device");
  unlink("/ctest/big");
  check(unlink("/ctest") == 0, "fixture cleanup");
  printf("ALL CONTAINER TESTS PASSED\n");
  exit(0);
}
