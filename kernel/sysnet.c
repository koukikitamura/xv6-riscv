//
// network system calls: listen() and accept().
//
// a socket is a struct file of type FD_SOCK, so read(), write() and
// close() on it go through file.c to sockread(), sockwrite() and
// sockclose() in tcp.c. only these two calls are network-specific.
//

#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// same as fdalloc() in sysfile.c, which is static there.
static int
fdalloc(struct file *f)
{
  int fd;
  struct proc *p = myproc();

  for (fd = 0; fd < NOFILE; fd++) {
    if (p->ofile[fd] == 0) {
      p->ofile[fd] = f;
      return fd;
    }
  }
  return -1;
}

// int listen(int port)
// returns a listening socket fd, or -1.
uint64
sys_listen(void)
{
  int port;
  struct file *f;
  struct sock *s;
  int fd;

  argint(0, &port);
  if (port <= 0 || port > 65535)
    return -1;

  if ((f = filealloc()) == 0)
    return -1;
  if ((s = socklisten(port)) == 0) {
    fileclose(f);
    return -1;
  }

  f->type = FD_SOCK;
  f->readable = 0; // a listener only accepts; read/write on it fail
  f->writable = 0;
  f->sock = s;

  if ((fd = fdalloc(f)) < 0) {
    fileclose(f); // closes s too
    return -1;
  }
  return fd;
}

// int accept(int fd)
// waits for a connection on listening socket fd and returns a new fd
// for it, or -1.
uint64
sys_accept(void)
{
  int lfd, fd;
  struct file *lf, *f;
  struct sock *s;

  argint(0, &lfd);
  if (lfd < 0 || lfd >= NOFILE || (lf = myproc()->ofile[lfd]) == 0)
    return -1;
  if (lf->type != FD_SOCK)
    return -1;

  if ((f = filealloc()) == 0)
    return -1;
  if ((s = sockaccept(lf->sock)) == 0) {
    fileclose(f);
    return -1;
  }

  f->type = FD_SOCK;
  f->readable = 1;
  f->writable = 1;
  f->sock = s;

  if ((fd = fdalloc(f)) < 0) {
    fileclose(f); // closes s too
    return -1;
  }
  return fd;
}
