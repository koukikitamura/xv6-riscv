// Shared container ABI. Memory includes page-rounded user address reservations,
// including lazy sbrk and the stack guard; kernel allocations are not charged.
#define CONTAINER_PERIOD 10000000UL // one second on QEMU virt

struct container_limits {
  uint64 memory;
  int maxprocs;
  int cpus;
};

struct procinfo {
  int pid;
  int container;
  int state;
  char name[16];
  uint64 runtime; // aggregate scheduled time, in QEMU timebase units
};
