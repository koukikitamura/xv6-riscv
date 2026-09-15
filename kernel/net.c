//
// Ethernet, ARP and IPv4.
//
// receive: virtio_net_intr() -> net_rx() -> arp_rx() or ip_rx() -> tcp_rx()
// send:    tcp.c -> net_tx() -> virtio_net_send()
//
// there is exactly one NIC, one fixed IP address (LOCAL_IP) and no
// routing: a reply always goes back to the MAC the request came from.
// so ARP only answers requests for our address; there is no ARP cache
// and we never send ARP requests ourselves.
//

#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "net.h"

struct spinlock netlock;

// scratch buffer for building outgoing frames. protected by netlock.
// (not on the stack: the kernel stack is only one page.)
static char txframe[ETH_MAXLEN];

void
netinit(void)
{
  initlock(&netlock, "net");
}

// Internet checksum (RFC 1071), computed byte-wise so it works on the
// unaligned headers inside an Ethernet frame. add data to sum with
// net_csum_add(), possibly several times, then finish with
// net_csum_fold(). the result is in network byte order.
uint32
net_csum_add(uint32 sum, void *data, int len)
{
  uint8 *p = data;
  for (int i = 0; i + 1 < len; i += 2)
    sum += (p[i] << 8) | p[i + 1];
  if (len & 1)
    sum += p[len - 1] << 8;
  return sum;
}

uint16
net_csum_fold(uint32 sum)
{
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return htons(~sum & 0xffff);
}

// answer "who has LOCAL_IP?" with our MAC. everything else is ignored.
// caller holds netlock.
static void
arp_rx(struct eth_hdr *eth, int len)
{
  if (len < sizeof(*eth) + sizeof(struct arp_pkt))
    return;
  struct arp_pkt *req = (struct arp_pkt *)(eth + 1);

  if (ntohs(req->htype) != ARP_HTYPE_ETH || ntohs(req->ptype) != ETHTYPE_IP ||
      req->hlen != ETH_ALEN || req->plen != 4)
    return;
  if (ntohs(req->op) != ARP_OP_REQUEST || ntohl(req->tpa) != LOCAL_IP)
    return;

  uint32 spa = ntohl(req->spa);
  netlog("arp: request from %d.%d.%d.%d, replying\n", spa >> 24,
         (spa >> 16) & 0xff, (spa >> 8) & 0xff, spa & 0xff);

  struct eth_hdr *reth = (struct eth_hdr *)txframe;
  struct arp_pkt *rep = (struct arp_pkt *)(reth + 1);

  memmove(reth->dst, eth->src, ETH_ALEN);
  memmove(reth->src, local_mac, ETH_ALEN);
  reth->type = htons(ETHTYPE_ARP);

  rep->htype = htons(ARP_HTYPE_ETH);
  rep->ptype = htons(ETHTYPE_IP);
  rep->hlen = ETH_ALEN;
  rep->plen = 4;
  rep->op = htons(ARP_OP_REPLY);
  memmove(rep->sha, local_mac, ETH_ALEN);
  rep->spa = htonl(LOCAL_IP);
  memmove(rep->tha, req->sha, ETH_ALEN);
  rep->tpa = req->spa;

  virtio_net_send(txframe, sizeof(*reth) + sizeof(*rep));
}

// accept an IPv4 packet for us and pass TCP up. no options, no
// fragments, no other protocols. caller holds netlock.
static void
ip_rx(struct eth_hdr *eth, int len)
{
  if (len < sizeof(*eth) + sizeof(struct ip_hdr))
    return;
  struct ip_hdr *ip = (struct ip_hdr *)(eth + 1);

  if (ip->vhl != 0x45) // not IPv4, or has options
    return;
  if (ntohl(ip->dst) != LOCAL_IP)
    return;
  if (ntohs(ip->off) & 0x3fff) // fragment offset or "more fragments"
    return;

  int iplen = ntohs(ip->len);
  if (iplen < sizeof(*ip) || iplen > len - sizeof(*eth)) // truncated
    return;

  if (ip->proto == IPPROTO_TCP)
    tcp_rx(eth, ip, iplen - sizeof(*ip));
}

// called by virtio_net_intr() for every received Ethernet frame.
void
net_rx(char *frame, int len)
{
  if (len < sizeof(struct eth_hdr))
    return;
  struct eth_hdr *eth = (struct eth_hdr *)frame;
  int type = ntohs(eth->type);

  acquire(&netlock);
  netlog("net_rx: type 0x%x len %d\n", type, len);
  if (type == ETHTYPE_ARP)
    arp_rx(eth, len);
  else if (type == ETHTYPE_IP)
    ip_rx(eth, len);
  release(&netlock);
}

// wrap payload (a TCP segment) in IP and Ethernet headers and send it.
// caller holds netlock.
void
net_tx(uint8 *dst_mac, uint32 dst_ip, uint8 proto, char *payload, int len)
{
  static uint16 ipid = 0;

  if (sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + len > ETH_MAXLEN)
    panic("net_tx: too long");

  struct eth_hdr *eth = (struct eth_hdr *)txframe;
  struct ip_hdr *ip = (struct ip_hdr *)(eth + 1);

  memmove(eth->dst, dst_mac, ETH_ALEN);
  memmove(eth->src, local_mac, ETH_ALEN);
  eth->type = htons(ETHTYPE_IP);

  ip->vhl = 0x45;
  ip->tos = 0;
  ip->len = htons(sizeof(*ip) + len);
  ip->id = htons(ipid++);
  ip->off = htons(0x4000); // don't fragment
  ip->ttl = 64;
  ip->proto = proto;
  ip->sum = 0;
  ip->src = htonl(LOCAL_IP);
  ip->dst = htonl(dst_ip);
  ip->sum = net_csum_fold(net_csum_add(0, ip, sizeof(*ip)));

  memmove(ip + 1, payload, len);

  netlog("net_tx: proto %d len %d\n", proto, len);
  virtio_net_send(txframe, sizeof(*eth) + sizeof(*ip) + len);
}
