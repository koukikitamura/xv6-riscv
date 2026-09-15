//
// driver for qemu's virtio network device.
// uses qemu's mmio interface to virtio, exactly like virtio_disk.c.
//
// qemu ... -netdev user,id=net0,hostfwd=tcp::8080-:80
//          -device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.1
//
// the device has two queues: 0 receives, 1 transmits. each descriptor
// is used on its own (no chains) and always points at the same buffer,
// so descriptor i and buffer i mean the same thing.
//
// the driver never sleeps, so it can be called from interrupt context
// (e.g. to send a TCP ACK while handling the received segment).
//

#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "virtio.h"
#include "net.h"

// the address of virtio mmio register r.
#define R(r) ((volatile uint32 *)(VIRTIO1 + (r)))

// registers not in virtio.h. the feature bits are read and written
// 32 bits at a time; these select which 32 bits.
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#define VIRTIO_MMIO_CONFIG              0x100 // device config space

// feature bits we accept. everything else (checksum offload, GSO,
// mergeable receive buffers, control queue, ...) is rejected so that
// what we get and give is a plain Ethernet frame.
#define VIRTIO_NET_F_MAC   5  // device has a MAC address in config space
#define VIRTIO_F_VERSION_1 32 // bit 0 of the second feature word

// avail ring flag: driver does not want an interrupt for this queue.
#define VRING_AVAIL_F_NO_INTERRUPT 1

// header the device puts in front of every frame, in both directions.
// with VIRTIO_F_VERSION_1 negotiated it is always this 12-byte form.
// we do no offloading, so on transmit every field is zero and on
// receive we just skip it.
struct virtio_net_hdr {
  uint8 flags;
  uint8 gso_type;
  uint16 hdr_len;
  uint16 gso_size;
  uint16 csum_start;
  uint16 csum_offset;
  uint16 num_buffers;
} __attribute__((packed));

#define NET_BUFSIZE 2048 // sizeof(virtio_net_hdr) + ETH_MAXLEN fits with room

// one virtqueue.
struct netq {
  struct virtq_desc *desc;   // NUM descriptors
  struct virtq_avail *avail; // driver -> device
  struct virtq_used *used;   // device -> driver
  uint16 used_idx;           // we've consumed used->ring up to here
  char *buf[NUM];            // NET_BUFSIZE bytes each, kalloc'd once at init
  char free[NUM];            // tx only: is slot i available for a new frame?
};

static struct net {
  struct netq rx; // queue 0: all NUM buffers stay posted; refilled after use
  struct netq tx; // queue 1: virtio_net_send() copies into a free slot
  struct spinlock lock; // lock order: netlock -> net.lock, never the reverse
} net;

uint8 local_mac[ETH_ALEN]; // read from config space at init

// allocate the descriptor table and rings for queue qnum and tell
// the device where they are. same steps as virtio_disk_init().
static void
initq(struct netq *q, int qnum)
{
  *R(VIRTIO_MMIO_QUEUE_SEL) = qnum;

  if (*R(VIRTIO_MMIO_QUEUE_READY))
    panic("virtio net should not be ready");

  uint32 max = *R(VIRTIO_MMIO_QUEUE_NUM_MAX);
  if (max == 0)
    panic("virtio net has no queue");
  if (max < NUM)
    panic("virtio net max queue too short");

  q->desc = kalloc();
  q->avail = kalloc();
  q->used = kalloc();
  if (!q->desc || !q->avail || !q->used)
    panic("virtio net kalloc");
  memset(q->desc, 0, PGSIZE);
  memset(q->avail, 0, PGSIZE);
  memset(q->used, 0, PGSIZE);

  for (int i = 0; i < NUM; i++) {
    q->buf[i] = kalloc();
    if (!q->buf[i])
      panic("virtio net kalloc buf");
  }

  *R(VIRTIO_MMIO_QUEUE_NUM) = NUM;

  *R(VIRTIO_MMIO_QUEUE_DESC_LOW) = (uint64)q->desc;
  *R(VIRTIO_MMIO_QUEUE_DESC_HIGH) = (uint64)q->desc >> 32;
  *R(VIRTIO_MMIO_DRIVER_DESC_LOW) = (uint64)q->avail;
  *R(VIRTIO_MMIO_DRIVER_DESC_HIGH) = (uint64)q->avail >> 32;
  *R(VIRTIO_MMIO_DEVICE_DESC_LOW) = (uint64)q->used;
  *R(VIRTIO_MMIO_DEVICE_DESC_HIGH) = (uint64)q->used >> 32;

  *R(VIRTIO_MMIO_QUEUE_READY) = 0x1;
}

void
virtio_net_init(void)
{
  uint32 status = 0;

  initlock(&net.lock, "virtio_net");

  if (*R(VIRTIO_MMIO_MAGIC_VALUE) != 0x74726976 ||
      *R(VIRTIO_MMIO_VERSION) != 2 || *R(VIRTIO_MMIO_DEVICE_ID) != 1 ||
      *R(VIRTIO_MMIO_VENDOR_ID) != 0x554d4551) {
    panic("could not find virtio net");
  }

  // reset device
  *R(VIRTIO_MMIO_STATUS) = status;

  // set ACKNOWLEDGE status bit
  status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;
  *R(VIRTIO_MMIO_STATUS) = status;

  // set DRIVER status bit
  status |= VIRTIO_CONFIG_S_DRIVER;
  *R(VIRTIO_MMIO_STATUS) = status;

  // negotiate features: keep only MAC (word 0) and VERSION_1 (word 1).
  *R(VIRTIO_MMIO_DEVICE_FEATURES_SEL) = 0;
  uint32 features0 = *R(VIRTIO_MMIO_DEVICE_FEATURES);
  if (!(features0 & (1 << VIRTIO_NET_F_MAC)))
    panic("virtio net has no MAC");
  *R(VIRTIO_MMIO_DRIVER_FEATURES_SEL) = 0;
  *R(VIRTIO_MMIO_DRIVER_FEATURES) = 1 << VIRTIO_NET_F_MAC;

  *R(VIRTIO_MMIO_DEVICE_FEATURES_SEL) = 1;
  uint32 features1 = *R(VIRTIO_MMIO_DEVICE_FEATURES);
  if (!(features1 & (1 << (VIRTIO_F_VERSION_1 - 32))))
    panic("virtio net is not version 1");
  *R(VIRTIO_MMIO_DRIVER_FEATURES_SEL) = 1;
  *R(VIRTIO_MMIO_DRIVER_FEATURES) = 1 << (VIRTIO_F_VERSION_1 - 32);

  // tell device that feature negotiation is complete.
  status |= VIRTIO_CONFIG_S_FEATURES_OK;
  *R(VIRTIO_MMIO_STATUS) = status;

  // re-read status to ensure FEATURES_OK is set.
  status = *R(VIRTIO_MMIO_STATUS);
  if (!(status & VIRTIO_CONFIG_S_FEATURES_OK))
    panic("virtio net FEATURES_OK unset");

  // our MAC address is the first 6 bytes of the config space.
  for (int i = 0; i < ETH_ALEN; i++)
    local_mac[i] =
      *(volatile uint8 *)(uint64)(VIRTIO1 + VIRTIO_MMIO_CONFIG + i);

  // receive queue: hand every buffer to the device, writable.
  initq(&net.rx, 0);
  for (int i = 0; i < NUM; i++) {
    net.rx.desc[i].addr = (uint64)net.rx.buf[i];
    net.rx.desc[i].len = NET_BUFSIZE;
    net.rx.desc[i].flags = VRING_DESC_F_WRITE; // device writes the buffer
    net.rx.desc[i].next = 0;
    net.rx.avail->ring[i] = i;
  }
  net.rx.avail->idx = NUM;

  // transmit queue: all slots free. we reclaim finished slots lazily
  // in virtio_net_send(), so ask the device not to interrupt for them.
  initq(&net.tx, 1);
  for (int i = 0; i < NUM; i++)
    net.tx.free[i] = 1;
  net.tx.avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  // tell device we're completely ready.
  status |= VIRTIO_CONFIG_S_DRIVER_OK;
  *R(VIRTIO_MMIO_STATUS) = status;

  // now that the device is running, tell it the receive buffers are there.
  io_fence();
  *R(VIRTIO_MMIO_QUEUE_NOTIFY) = 0;

  printk("virtio net: mac %x:%x:%x:%x:%x:%x\n", local_mac[0], local_mac[1],
         local_mac[2], local_mac[3], local_mac[4], local_mac[5]);

  // plic.c and trap.c arrange for interrupts from VIRTIO1_IRQ.
}

// mark transmit slots the device has finished with as free again.
// caller holds net.lock.
static void
reclaim_tx(void)
{
  while (net.tx.used_idx != net.tx.used->idx) {
    io_fence();
    int id = net.tx.used->ring[net.tx.used_idx % NUM].id;
    if (id >= NUM || net.tx.free[id])
      panic("virtio_net reclaim");
    net.tx.free[id] = 1;
    net.tx.used_idx += 1;
  }
}

// send one Ethernet frame. copies it, so the caller's buffer can be
// reused as soon as this returns. does not wait for the device.
void
virtio_net_send(char *frame, int len)
{
  if (len > ETH_MAXLEN)
    panic("virtio_net_send: frame too long");

  acquire(&net.lock);

  // find a free slot. if all NUM are still with the device, spin a
  // while: qemu drains the queue in another thread, so this is short.
  int i = -1;
  for (int tries = 0; i < 0 && tries < 10000000; tries++) {
    reclaim_tx();
    for (int j = 0; j < NUM; j++) {
      if (net.tx.free[j]) {
        i = j;
        break;
      }
    }
  }
  if (i < 0) {
    printk("virtio_net_send: transmit queue stuck, dropping frame\n");
    release(&net.lock);
    return;
  }
  net.tx.free[i] = 0;

  // header (all zero) followed by the frame, in one buffer.
  struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)net.tx.buf[i];
  memset(hdr, 0, sizeof(*hdr));
  memmove(net.tx.buf[i] + sizeof(*hdr), frame, len);

  net.tx.desc[i].addr = (uint64)net.tx.buf[i];
  net.tx.desc[i].len = sizeof(*hdr) + len;
  net.tx.desc[i].flags = 0; // device reads the buffer
  net.tx.desc[i].next = 0;

  // tell the device the descriptor is available.
  net.tx.avail->ring[net.tx.avail->idx % NUM] = i;
  io_fence();
  net.tx.avail->idx += 1;
  io_fence();
  *R(VIRTIO_MMIO_QUEUE_NOTIFY) = 1; // value is queue number

  release(&net.lock);
}

// a frame arrived (or several). hand each one to net_rx() and give
// the buffer back to the device.
void
virtio_net_intr(void)
{
  acquire(&net.lock);

  // the device won't raise another interrupt until we tell it
  // we've seen this interrupt, which the following line does.
  *R(VIRTIO_MMIO_INTERRUPT_ACK) = *R(VIRTIO_MMIO_INTERRUPT_STATUS) & 0x3;

  io_fence();

  while (net.rx.used_idx != net.rx.used->idx) {
    io_fence();
    int id = net.rx.used->ring[net.rx.used_idx % NUM].id;
    int len = net.rx.used->ring[net.rx.used_idx % NUM].len;
    net.rx.used_idx += 1;
    if (id >= NUM)
      panic("virtio_net_intr id");

    // hand the Ethernet frame (after the virtio header) to the protocol
    // code without holding net.lock: net_rx() may send a reply, and
    // virtio_net_send() takes net.lock. the buffer is safe meanwhile
    // because it is not in the avail ring until we put it back below.
    release(&net.lock);
    if (len > sizeof(struct virtio_net_hdr))
      net_rx(net.rx.buf[id] + sizeof(struct virtio_net_hdr),
             len - sizeof(struct virtio_net_hdr));
    acquire(&net.lock);

    // give the buffer back to the device.
    net.rx.avail->ring[net.rx.avail->idx % NUM] = id;
    io_fence();
    net.rx.avail->idx += 1;
    io_fence();
    *R(VIRTIO_MMIO_QUEUE_NOTIFY) = 0;
  }

  release(&net.lock);
}
