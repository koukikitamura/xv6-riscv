#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if (t == SBRK_EAGER || n < 0) {
    if (growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if (addr + n < addr)
      return -1;
    if (addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if (n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n) {
    if (killed(myproc())) {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_getuid(void)
{
  return myproc()->uid;
}

uint64
sys_getgid(void)
{
  return myproc()->gid;
}

// No saved IDs or setuid executables: dropping root is irreversible.
uint64
sys_setidentity(void)
{
  int uid, gid;
  struct proc *p = myproc();

  argint(0, &uid);
  argint(1, &gid);

  if (p->uid != 0)
    return -1;
  if (uid < 0 || uid > 65535 || gid < 0 || gid > 65535)
    return -1;

  acquire(&p->lock);
  p->uid = uid;
  p->gid = gid;
  release(&p->lock);

  return 0;
}

uint64
sys_consoleset(void)
{
  int uid, echo;

  argint(0, &uid);
  argint(1, &echo);

  if (myproc()->uid != 0)
    return -1;
  if (uid < 0 || uid > 65535)
    return -1;
  if (echo != 0 && echo != 1)
    return -1;

  return consoleset(uid, echo);
}
