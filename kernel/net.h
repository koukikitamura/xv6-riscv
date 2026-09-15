//
// network definitions: byte order, packet headers, sockets.
//
// RISC-V is little-endian; everything on the wire is big-endian,
// so every multi-byte header field goes through htons/htonl.
//
// the whole stack is deliberately small: one NIC, one fixed IP,
// TCP server side only, no retransmission. see net.c and tcp.c.
//

// set to 1 to printk a one-line summary of every frame in and out.
#define NET_DEBUG 0
#define netlog(...)                                                            \
  do {                                                                         \
    if (NET_DEBUG)                                                             \
      printk(__VA_ARGS__);                                                     \
  } while (0)

static inline uint16
htons(uint16 v)
{
  return (v >> 8) | (v << 8);
}
static inline uint16
ntohs(uint16 v)
{
  return htons(v);
}
static inline uint32
htonl(uint32 v)
{
  return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) |
         (v >> 24);
}
static inline uint32
ntohl(uint32 v)
{
  return htonl(v);
}

// fixed configuration. qemu's user-mode network always gives the
// guest 10.0.2.15, so there is no DHCP.
#define LOCAL_IP   0x0a00020f // 10.0.2.15, host byte order
#define ETH_ALEN   6
#define ETH_MAXLEN 1514 // 14-byte header + 1500-byte payload
#define TCP_MSS    1460 // 1500 - 20 (IP) - 20 (TCP)

extern uint8 local_mac[ETH_ALEN]; // filled in by virtio_net_init()

// one lock for all protocol state: the socket table, every TCP
// connection, and the transmit scratch buffers. taken by net_rx()
// (interrupt context) and by the socket system calls.
extern struct spinlock netlock;

// Ethernet
#define ETHTYPE_IP  0x0800
#define ETHTYPE_ARP 0x0806
struct eth_hdr {
  uint8 dst[ETH_ALEN];
  uint8 src[ETH_ALEN];
  uint16 type;
} __attribute__((packed));

// ARP, Ethernet/IPv4 only.
#define ARP_HTYPE_ETH  1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2
struct arp_pkt {
  uint16 htype;        // ARP_HTYPE_ETH
  uint16 ptype;        // ETHTYPE_IP
  uint8 hlen;          // 6
  uint8 plen;          // 4
  uint16 op;           // ARP_OP_REQUEST or ARP_OP_REPLY
  uint8 sha[ETH_ALEN]; // sender MAC
  uint32 spa;          // sender IP
  uint8 tha[ETH_ALEN]; // target MAC
  uint32 tpa;          // target IP
} __attribute__((packed));

// IPv4. no options, no fragments.
#define IPPROTO_TCP 6
struct ip_hdr {
  uint8 vhl; // version 4, header length 5 words -> always 0x45
  uint8 tos;
  uint16 len; // total length including this header
  uint16 id;
  uint16 off; // flags + fragment offset, always 0 when we send
  uint8 ttl;
  uint8 proto; // IPPROTO_TCP
  uint16 sum;  // header checksum
  uint32 src;
  uint32 dst;
} __attribute__((packed));

// TCP. we never send options and ignore whatever the peer sends.
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
struct tcp_hdr {
  uint16 sport;
  uint16 dport;
  uint32 seq;
  uint32 ack;
  uint8 off;   // upper 4 bits: header length in 32-bit words
  uint8 flags; // TCP_FIN | TCP_SYN | ...
  uint16 win;  // receive window
  uint16 sum;
  uint16 urg;
} __attribute__((packed));

// pseudo header that prefixes the TCP segment when computing its checksum.
struct tcp_pseudo {
  uint32 src;
  uint32 dst;
  uint8 zero;
  uint8 proto;
  uint16 len; // TCP header + data length
} __attribute__((packed));

//
// sockets. one table entry is either a listener or a connection.
//
#define NSOCK      16
#define SOCK_RXBUF 4096

enum sockstate {
  SOCK_FREE = 0,
  SOCK_LISTEN,   // created by listen(port)
  SOCK_SYN_RCVD, // got SYN, sent SYN+ACK, waiting for ACK
  SOCK_ESTABLISHED,
  SOCK_CLOSE_WAIT, // peer sent FIN; we haven't closed yet
  SOCK_LAST_ACK,   // we closed from CLOSE_WAIT; waiting for ACK of our FIN
  SOCK_FIN_WAIT_1, // we closed from ESTABLISHED; waiting for ACK of our FIN
  SOCK_FIN_WAIT_2, // our FIN was ACKed; waiting for peer's FIN
                   // (no TIME_WAIT: we are done as soon as we ACK that FIN)
  SOCK_CLOSED,     // TCP is over (RST, or FINs exchanged) but a struct file
                   // still points here; close() turns this into SOCK_FREE
};

struct sock {
  enum sockstate state;
  uint16 lport; // local port (listener and connection)

  // the rest is only meaningful for connections (state >= SOCK_SYN_RCVD).
  struct sock *listener; // the listener this connection was born from
  int accepted;          // 1 while a struct file refers to this entry,
                         // i.e. from accept() until close()
  uint32 rip;            // peer IP
  uint16 rport;          // peer port
  uint8 rmac[ETH_ALEN];  // peer MAC, copied from the SYN's Ethernet source

  uint32 snd_nxt; // sequence number of the next byte we send
  uint32 snd_una; // oldest byte not yet ACKed by the peer
  uint16 snd_wnd; // peer's receive window, from the last segment it sent
  uint32 rcv_nxt; // sequence number we expect next (= ACK we send)

  // receive ring, same scheme as pipe.c: nread/nwrite only grow, the
  // position is n % SOCK_RXBUF, full when nwrite == nread + SOCK_RXBUF.
  // the window we advertise is the free space.
  char rxbuf[SOCK_RXBUF];
  uint nread;
  uint nwrite;

  uint close_tick; // ticks when we entered FIN_WAIT_1/LAST_ACK, for GC
};
