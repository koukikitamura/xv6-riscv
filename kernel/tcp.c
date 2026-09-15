//
// TCP, server side only, and the socket table.
//
// what this does: accept connections on a listening port, receive data
// in order into a per-connection ring, send data within the peer's
// window, and close cleanly from either side.
//
// what this deliberately does not do: open connections, retransmit
// (qemu's user-mode network does not lose packets), reorder segments
// (anything out of order is dropped and the peer resends it), TIME_WAIT,
// congestion control, options, urgent data.
//
// all state lives in nettable.socks[] and is protected by netlock.
// tcp_rx() runs in interrupt context; the sock*() functions run in
// process context and sleep on the sock entry when they have to wait.
//

#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "net.h"

static struct {
  struct sock socks[NSOCK];
} nettable;

// scratch buffer for building one outgoing segment. protected by netlock.
static char seg[sizeof(struct tcp_hdr) + TCP_MSS];

// a connection that finished closing is kept this long (in ticks,
// 10 per second) in case the peer's last packet is late, then reused.
#define LINGER_TICKS 50

// sequence number arithmetic wraps, so compare with a signed difference.
static int
seq_lt(uint32 a, uint32 b)
{
  return (int)(a - b) < 0;
}

// free space in the receive ring, which is also the window we advertise.
static int
rxfree(struct sock *s)
{
  return SOCK_RXBUF - (s->nwrite - s->nread);
}

// wake every process that may be waiting on this connection.
static void
sockwakeup(struct sock *s)
{
  wakeup(&s->nread);   // readers
  wakeup(&s->snd_una); // writers
  if (s->listener)
    wakeup(s->listener); // accept()
}

// find a free table entry. if the table is full, reclaim a connection
// that finished long ago but whose peer never sent the last packet.
static struct sock *
sockalloc(void)
{
  struct sock *s;

  for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++)
    if (s->state == SOCK_FREE)
      break;

  if (s == &nettable.socks[NSOCK]) {
    for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++) {
      if ((s->state == SOCK_FIN_WAIT_1 || s->state == SOCK_FIN_WAIT_2 ||
           s->state == SOCK_LAST_ACK) &&
          ticks - s->close_tick > LINGER_TICKS)
        break;
    }
    if (s == &nettable.socks[NSOCK])
      return 0;
  }

  memset(s, 0, sizeof(*s));
  return s;
}

// build and send one segment on connection s, carrying flags and
// len bytes of data, and advance snd_nxt past it. caller holds netlock.
static void
tcp_send(struct sock *s, uint8 flags, char *data, int len)
{
  struct tcp_hdr *tcp = (struct tcp_hdr *)seg;

  tcp->sport = htons(s->lport);
  tcp->dport = htons(s->rport);
  tcp->seq = htonl(s->snd_nxt);
  tcp->ack = htonl(s->rcv_nxt);
  tcp->off = (sizeof(*tcp) / 4) << 4;
  tcp->flags = flags;
  tcp->win = htons(rxfree(s));
  tcp->sum = 0;
  tcp->urg = 0;
  if (len > 0)
    memmove(tcp + 1, data, len);

  struct tcp_pseudo ph = {
    .src = htonl(LOCAL_IP),
    .dst = htonl(s->rip),
    .zero = 0,
    .proto = IPPROTO_TCP,
    .len = htons(sizeof(*tcp) + len),
  };
  uint32 sum = net_csum_add(0, &ph, sizeof(ph));
  sum = net_csum_add(sum, seg, sizeof(*tcp) + len);
  tcp->sum = net_csum_fold(sum);

  netlog("tcp_send: %d -> %d flags 0x%x seq %u ack %u len %d\n", s->lport,
         s->rport, flags, s->snd_nxt, s->rcv_nxt, len);

  net_tx(s->rmac, s->rip, IPPROTO_TCP, seg, sizeof(*tcp) + len);

  s->snd_nxt += len;
  if (flags & TCP_SYN)
    s->snd_nxt += 1;
  if (flags & TCP_FIN)
    s->snd_nxt += 1;
}

// reply with RST to a segment that has no connection, so the peer
// gives up immediately instead of waiting for a timeout. this is what
// happens when nobody is listening on the port. caller holds netlock.
static void
tcp_send_rst(struct eth_hdr *eth, struct ip_hdr *ip, struct tcp_hdr *in,
             int datalen)
{
  struct tcp_hdr *tcp = (struct tcp_hdr *)seg;

  tcp->sport = in->dport;
  tcp->dport = in->sport;
  if (in->flags & TCP_ACK) {
    // the peer told us what it expects next; use that so it accepts the RST.
    tcp->seq = in->ack;
    tcp->ack = 0;
    tcp->flags = TCP_RST;
  } else {
    // no ACK to take a sequence number from (e.g. a SYN): ACK what we got.
    uint32 ack = ntohl(in->seq) + datalen;
    if (in->flags & TCP_SYN)
      ack += 1;
    if (in->flags & TCP_FIN)
      ack += 1;
    tcp->seq = 0;
    tcp->ack = htonl(ack);
    tcp->flags = TCP_RST | TCP_ACK;
  }
  tcp->off = (sizeof(*tcp) / 4) << 4;
  tcp->win = 0;
  tcp->sum = 0;
  tcp->urg = 0;

  struct tcp_pseudo ph = {
    .src = ip->dst,
    .dst = ip->src,
    .zero = 0,
    .proto = IPPROTO_TCP,
    .len = htons(sizeof(*tcp)),
  };
  uint32 sum = net_csum_add(0, &ph, sizeof(ph));
  sum = net_csum_add(sum, seg, sizeof(*tcp));
  tcp->sum = net_csum_fold(sum);

  netlog("tcp_send_rst: port %d\n", ntohs(in->dport));

  net_tx(eth->src, ntohl(ip->src), IPPROTO_TCP, seg, sizeof(*tcp));
}

// the TCP conversation on s is over. if a process still holds it,
// keep the entry so read() can report EOF and close() can free it;
// otherwise free it now. caller holds netlock.
static void
tcp_done(struct sock *s)
{
  s->state = s->accepted ? SOCK_CLOSED : SOCK_FREE;
  sockwakeup(s);
}

// a SYN arrived for listener l: create the connection and answer SYN+ACK.
// caller holds netlock.
static void
tcp_rx_syn(struct sock *l, struct eth_hdr *eth, struct ip_hdr *ip,
           struct tcp_hdr *tcp)
{
  static uint32 iss = 0; // initial sequence number; any value works

  struct sock *s = sockalloc();
  if (s == 0) {
    printk("tcp: socket table full, dropping SYN\n");
    return;
  }

  iss += 0x10000;
  s->state = SOCK_SYN_RCVD;
  s->lport = l->lport;
  s->listener = l;
  s->rip = ntohl(ip->src);
  s->rport = ntohs(tcp->sport);
  memmove(s->rmac, eth->src, ETH_ALEN);
  s->rcv_nxt = ntohl(tcp->seq) + 1; // the SYN takes one sequence number
  s->snd_una = iss;
  s->snd_nxt = iss;
  s->snd_wnd = ntohs(tcp->win);

  tcp_send(s, TCP_SYN | TCP_ACK, 0, 0);
}

// called by ip_rx() for every TCP segment addressed to us.
// tcplen is the length of header plus data. caller holds netlock.
void
tcp_rx(struct eth_hdr *eth, struct ip_hdr *ip, int tcplen)
{
  struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);
  struct sock *s;

  if (tcplen < sizeof(*tcp))
    return;
  int hdrlen = (tcp->off >> 4) * 4;
  if (hdrlen < sizeof(*tcp) || hdrlen > tcplen)
    return;
  char *data = (char *)tcp + hdrlen;
  int datalen = tcplen - hdrlen;

  uint32 rip = ntohl(ip->src);
  uint16 rport = ntohs(tcp->sport);
  uint16 lport = ntohs(tcp->dport);
  uint32 seq = ntohl(tcp->seq);
  uint32 ack = ntohl(tcp->ack);
  uint8 flags = tcp->flags;

  netlog("tcp_rx: %d -> %d flags 0x%x seq %u ack %u len %d\n", rport, lport,
         flags, seq, ack, datalen);

  // find the connection this segment belongs to.
  for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++) {
    if (s->state >= SOCK_SYN_RCVD && s->state != SOCK_CLOSED &&
        s->lport == lport && s->rport == rport && s->rip == rip)
      break;
  }

  if (s == &nettable.socks[NSOCK]) {
    // no connection. a SYN to a listening port starts one;
    // anything else gets a RST.
    for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++)
      if (s->state == SOCK_LISTEN && s->lport == lport)
        break;
    if (s != &nettable.socks[NSOCK] && (flags & TCP_SYN) && !(flags & TCP_ACK))
      tcp_rx_syn(s, eth, ip, tcp);
    else if (!(flags & TCP_RST))
      tcp_send_rst(eth, ip, tcp, datalen);
    return;
  }

  if (flags & TCP_RST) {
    tcp_done(s);
    return;
  }

  // handshake: our SYN+ACK is answered by an ACK.
  if (s->state == SOCK_SYN_RCVD) {
    if (flags & TCP_SYN) {
      // the peer resent its SYN; our SYN+ACK must have been lost. resend it.
      s->snd_nxt = s->snd_una;
      tcp_send(s, TCP_SYN | TCP_ACK, 0, 0);
      return;
    }
    if (!(flags & TCP_ACK) || ack != s->snd_nxt)
      return;
    s->state = SOCK_ESTABLISHED;
    // fall through: the ACK may carry data.
  }

  // the peer acknowledged some of what we sent, and told us its window.
  if (flags & TCP_ACK) {
    if (seq_lt(s->snd_una, ack) && !seq_lt(s->snd_nxt, ack))
      s->snd_una = ack;
    s->snd_wnd = ntohs(tcp->win);
    wakeup(&s->snd_una); // a writer may be waiting for room

    if (s->state == SOCK_FIN_WAIT_1 && s->snd_una == s->snd_nxt)
      s->state = SOCK_FIN_WAIT_2; // our FIN was ACKed
    if (s->state == SOCK_LAST_ACK && s->snd_una == s->snd_nxt) {
      tcp_done(s); // our FIN was ACKed; both sides are done
      return;
    }
  }

  // nothing more to do for a pure ACK.
  if (datalen == 0 && !(flags & TCP_FIN))
    goto wake;

  // we only take data in order. anything else (a retransmission of what
  // we already have, or a segment that arrived early) is answered with
  // an ACK saying what we do want, and dropped.
  if (seq != s->rcv_nxt) {
    tcp_send(s, TCP_ACK, 0, 0);
    goto wake;
  }

  // copy what fits into the receive ring; the rest is not ACKed
  // and the peer will resend it when we have room.
  int n = datalen;
  if (n > rxfree(s))
    n = rxfree(s);
  for (int i = 0; i < n; i++)
    s->rxbuf[s->nwrite++ % SOCK_RXBUF] = data[i];
  s->rcv_nxt += n;

  // the peer is done sending. the FIN counts as one sequence number.
  int fin = (flags & TCP_FIN) && n == datalen;
  if (fin)
    s->rcv_nxt += 1;

  tcp_send(s, TCP_ACK, 0, 0);

  if (fin) {
    if (s->state == SOCK_ESTABLISHED)
      s->state = SOCK_CLOSE_WAIT;
    else if (s->state == SOCK_FIN_WAIT_1 || s->state == SOCK_FIN_WAIT_2)
      tcp_done(s); // (FIN_WAIT_1: we skip CLOSING and assume our FIN got there)
  }

wake:
  sockwakeup(s);
}

//
// socket operations, called from sysnet.c and file.c.
//

// create a listening socket on port. returns 0 if the port is in use
// or the table is full.
struct sock *
socklisten(int port)
{
  struct sock *s;

  acquire(&netlock);
  for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++) {
    if (s->state == SOCK_LISTEN && s->lport == port) {
      release(&netlock);
      return 0;
    }
  }
  s = sockalloc();
  if (s) {
    s->state = SOCK_LISTEN;
    s->lport = port;
    s->accepted = 1;
  }
  release(&netlock);
  return s;
}

// wait for a connection to l and hand it out. returns 0 if l was
// closed or the process was killed.
struct sock *
sockaccept(struct sock *l)
{
  struct sock *s;
  struct proc *pr = myproc();

  acquire(&netlock);
  while (1) {
    if (l->state != SOCK_LISTEN || killed(pr)) {
      release(&netlock);
      return 0;
    }
    for (s = nettable.socks; s < &nettable.socks[NSOCK]; s++) {
      if (s->listener == l && !s->accepted &&
          (s->state == SOCK_ESTABLISHED || s->state == SOCK_CLOSE_WAIT)) {
        s->accepted = 1;
        release(&netlock);
        return s;
      }
    }
    sleep_prepare(l);
    release(&netlock);
    sleep();
    acquire(&netlock);
  }
}

// copy up to n received bytes to user address addr. blocks until there
// is something; returns 0 once the peer has closed and the ring is empty.
int
sockread(struct sock *s, uint64 addr, int n)
{
  int i;
  struct proc *pr = myproc();
  char ch;

  acquire(&netlock);
  while (s->nread == s->nwrite) {
    // empty. if no more data can arrive, that is end of file.
    if (s->state != SOCK_ESTABLISHED) {
      release(&netlock);
      return 0;
    }
    if (killed(pr)) {
      release(&netlock);
      return -1;
    }
    sleep_prepare(&s->nread);
    release(&netlock);
    sleep();
    acquire(&netlock);
  }

  int wasfull = (rxfree(s) == 0);
  for (i = 0; i < n; i++) {
    if (s->nread == s->nwrite)
      break;
    ch = s->rxbuf[s->nread % SOCK_RXBUF];
    if (copyout(pr->pagetable, pr->sz, addr + i, &ch, 1) == -1) {
      if (i == 0)
        i = -1;
      break;
    }
    s->nread++;
  }

  // if the ring was full the peer may have stopped sending;
  // tell it there is room again.
  if (wasfull && s->state == SOCK_ESTABLISHED)
    tcp_send(s, TCP_ACK, 0, 0);

  release(&netlock);
  return i;
}

// send n bytes from user address addr, one segment at a time, never
// having more than the peer's window in flight. returns the number
// of bytes sent, or -1 if the connection is gone.
int
sockwrite(struct sock *s, uint64 addr, int n)
{
  int i = 0;
  struct proc *pr = myproc();

  acquire(&netlock);
  while (i < n) {
    if ((s->state != SOCK_ESTABLISHED && s->state != SOCK_CLOSE_WAIT) ||
        killed(pr)) {
      if (i == 0)
        i = -1;
      break;
    }

    // flow control: wait until the peer has room for at least one byte.
    int inflight = s->snd_nxt - s->snd_una;
    int room = s->snd_wnd - inflight;
    if (room <= 0) {
      sleep_prepare(&s->snd_una);
      release(&netlock);
      sleep();
      acquire(&netlock);
      continue;
    }

    int len = n - i;
    if (len > TCP_MSS)
      len = TCP_MSS;
    if (len > room)
      len = room;

    // copy the data straight into the segment buffer.
    if (copyin(pr->pagetable, pr->sz, seg + sizeof(struct tcp_hdr), addr + i,
               len) == -1) {
      if (i == 0)
        i = -1;
      break;
    }
    tcp_send(s, TCP_ACK | TCP_PSH, seg + sizeof(struct tcp_hdr), len);
    i += len;
  }
  release(&netlock);
  return i;
}

// the last struct file referring to s is gone.
void
sockclose(struct sock *s)
{
  struct sock *c;

  acquire(&netlock);
  switch (s->state) {
  case SOCK_LISTEN:
    // connections that arrived but were never accept()ed are refused;
    // accepted ones just lose their back pointer.
    for (c = nettable.socks; c < &nettable.socks[NSOCK]; c++) {
      if (c->listener != s)
        continue;
      c->listener = 0;
      if (!c->accepted &&
          (c->state == SOCK_SYN_RCVD || c->state == SOCK_ESTABLISHED ||
           c->state == SOCK_CLOSE_WAIT)) {
        tcp_send(c, TCP_RST | TCP_ACK, 0, 0);
        c->state = SOCK_FREE;
      }
    }
    s->state = SOCK_FREE;
    wakeup(s); // anyone in accept() sees the state change
    break;
  case SOCK_ESTABLISHED:
    tcp_send(s, TCP_FIN | TCP_ACK, 0, 0);
    s->state = SOCK_FIN_WAIT_1;
    s->close_tick = ticks;
    break;
  case SOCK_CLOSE_WAIT:
    tcp_send(s, TCP_FIN | TCP_ACK, 0, 0);
    s->state = SOCK_LAST_ACK;
    s->close_tick = ticks;
    break;
  default:
    // SOCK_CLOSED: TCP already finished, nothing to send.
    s->state = SOCK_FREE;
    break;
  }
  s->accepted = 0;
  release(&netlock);
}
