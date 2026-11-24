# Questions about the HTTP-processing lab

## 1. What is `pcap_t`?

`pcap_t` is an **opaque handle**, which means you're not supposed to look inside it. It's the "capture session" object that libpcap gives you, a bit like how `FILE *` works with `fopen()`:

```c
FILE   *f  = fopen("file.txt", "r");        // handle to a file
pcap_t *ad = pcap_open_live("eth0", ...);   // handle to a capture session
```

Inside libpcap (in `pcap-int.h`, which is not a public header) it holds things like:

- the OS socket or file descriptor it reads packets from
- the internal receive buffer
- the snaplen (`65536` in your code), the timeout and the promiscuous flag
- the **link-layer type** of the interface (Ethernet, Wi-Fi, loopback...)
- any BPF filter you set, error strings, and so on

You never read its fields directly. You just pass it to other functions:

- `pcap_loop(adhandle, ...)`
- `pcap_close(adhandle)`
- `pcap_datalink(adhandle)`
- `pcap_setfilter(adhandle, ...)`

---

## 2. Why do we always start with the Ethernet frame?

Your two ideas ("always start with Ethernet" and "read the first bytes to find out what the packet is") are really the same idea, and you're right. Here's why.

### Small correction first

libpcap calls `packet_handler` **once per packet**, and `pkt_data` points to the start of *that one* packet. `header->caplen` tells you how many bytes in that buffer are valid, so you never read past it. You don't have to look for where one packet ends and the next one starts; libpcap already split them for you.

### Why Ethernet comes first: encapsulation

You can't read the first bytes and "guess" whether they're IP, TCP or UDP, because the protocols are **nested inside each other**. On an Ethernet interface, the first bytes are *always* the Ethernet header:

```
pkt_data
   |
   v
+--------------+-------------------+----------------+--------------+
| Ethernet hdr |     IP header     | TCP/UDP header |   payload    |
|   14 bytes   | 20-60 bytes (IHL) |  TCP: 20-60    | (e.g. HTTP)  |
|              |                   |  UDP: 8        |              |
+--------------+-------------------+----------------+--------------+
```

The IP header isn't at byte 0. It sits *inside* the Ethernet frame, and TCP/UDP sits *inside* the IP packet. So you have to parse from the outside in.

### Each layer tells you what the next one is

This is the key point. You don't guess anything. **Every header has a field that says what comes next:**

| Layer     | Field that names the next layer                                         | Field that gives the offset          |
|-----------|-------------------------------------------------------------------------|--------------------------------------|
| Ethernet  | `h_proto` (EtherType): `0x0800` = IPv4, `0x86DD` = IPv6, `0x0806` = ARP | fixed: 14 bytes                      |
| IP        | `ip_p` (protocol): `6` = TCP, `17` = UDP, `1` = ICMP                    | `(lenver & 0x0F) * 4` (IHL)          |
| TCP / UDP | destination/source port: `80` = HTTP, `53` = DNS...                     | TCP: data offset x 4; UDP: 8 bytes   |

So the parsing in this lab goes like this:

```c
struct ethhdr *eth = (struct ethhdr *) pkt_data;
if (ntohs(eth->h_proto) != 0x0800) return;             // not IPv4

struct ip_header *ip = (struct ip_header *)(pkt_data + 14);
int ip_hlen = (ip->lenver & 0x0F) * 4;                  // IP header length
if (ip->ip_p != 6) return;                              // not TCP

const u_char *tcp = pkt_data + 14 + ip_hlen;
int tcp_hlen = ((tcp[12] >> 4) & 0x0F) * 4;             // TCP data offset
const u_char *payload = tcp + tcp_hlen;                 // HTTP starts here
// always check you stay below pkt_data + header->caplen
```

That's exactly what your current code does for the first step: it casts to `ethhdr` and checks `h_proto == 0x800`. The next steps continue the same way.

### "Always Ethernet?" Not always

It depends on the **interface you capture on**, not on the packet. On `eth0` it's Ethernet. On other interfaces it isn't:

- Linux `any` uses an SLL header
- Wi-Fi in monitor mode uses 802.11 + radiotap
- some loopback captures use other headers

You can check with:

```c
if (pcap_datalink(adhandle) != DLT_EN10MB) {   // DLT_EN10MB = Ethernet
    fprintf(stderr, "Not an Ethernet interface\n");
}
```

For this lab you're on Ethernet, so starting with `ethhdr` at offset 0 is correct.

### Two details to remember

- Use `ntohs()` / `ntohl()` on multi-byte fields, because network byte order is big-endian.
- Your code prints `header->len`, which is the original length of the packet. Use `header->caplen` for bounds checks, because that's how many bytes you actually have.

---

## 3. Checking your understanding of the Ethernet frame

You're mostly right. There are two corrections and one missing piece.

### Why you don't see the Preamble (and FCS)

Looking at `ethernet-frame.png`:

```
| PREAMBLE | DEST ADDR | SRC ADDR | TYPE | DATA      | FCS |
|    8     |     6     |    6     |  2   | 46-1500   |  4  |
  ^^^^^^^^                                            ^^^^^
  removed by the network card (NIC) before libpcap sees the packet
```

- The **Preamble** (and the SOF byte in 802.3) is only a pattern of bits (`10101010...`) that lets the receiver's hardware **sync its clock** with the signal. Once the card has synced, the pattern has done its job, so the card throws it away. It never reaches memory.
- The **FCS** (a 4-byte checksum at the end) is checked by the card and then **usually removed** too. If it's wrong, the card drops the whole frame.

So what you get in `pkt_data` starts at **Destination Address**:

```
pkt_data[0..5]    -> destination MAC  (6 bytes)
pkt_data[6..11]   -> source MAC       (6 bytes)
pkt_data[12..13]  -> type             (2 bytes, big-endian -> use ntohs)
pkt_data[14...]   -> data (the next protocol's header starts here)
```

That's exactly `struct ethhdr` from `<linux/if_ether.h>`: `h_dest[6]`, `h_source[6]`, `h_proto`. It's **14 bytes**.

### Correction: Type does NOT tell you TCP or UDP

This is the most important correction. Each header only tells you about the **next layer**, never two layers down:

```
Ethernet.type  --> says: IPv4 / IPv6 / ARP / VLAN ...
                       (it does NOT know about TCP/UDP)
IP.protocol    --> says: TCP / UDP / ICMP ...
TCP/UDP.port   --> says (by convention): HTTP / DNS / ...
```

Common EtherType values:

| EtherType | Next protocol |
|-----------|---------------|
| `0x0800`  | IPv4          |
| `0x86DD`  | IPv6          |
| `0x0806`  | ARP           |
| `0x8100`  | VLAN tag (adds 4 more bytes before the real type) |

TCP and UDP are **never** EtherType values. You find them in the IP header's **Protocol** field (`6` = TCP, `17` = UDP, `1` = ICMP).

### Yes: `header->caplen` is your boundary

`caplen` is the number of bytes libpcap actually copied into `pkt_data`. Valid bytes are `pkt_data[0]` up to `pkt_data[caplen - 1]`. **Before you read any header, check that it fits:**

```c
if (header->caplen < 14) return;                  // not even a full Ethernet header
```

Then check again at every layer (see the full example below).

(`header->len` is the size the packet had on the wire. It can be bigger than `caplen` if you set a small snaplen. Never use `len` for bounds checks.)

---

## 4. "How do I know which fields are there and which are not?"

You don't have to guess this either. Every protocol has two kinds of headers.

### a) Fixed headers: always the same size and layout

- **Ethernet**: always 14 bytes, always the same 3 fields.
- **UDP**: always 8 bytes: src port, dst port, length, checksum.

For these you just cast a struct and read it.

### b) Variable headers: the header tells you its own size

Some headers have **optional fields** (the "Options" box in `ip.png`). The header always has a **length field** at the start that says how big the header really is, so you know where it ends.

**IPv4** (`ip.png`): the first 20 bytes are always there. Then there are 0 to 40 bytes of options.

```
byte 0 = | Version (4 bits) | IHL (4 bits) |
```

- `Version` = 4 for IPv4
- `IHL` = header length **in 32-bit words** (groups of 4 bytes) -> `ip_header_len = IHL * 4`
  - IHL = 5  -> 20 bytes (no options, the most common case)
  - IHL = 15 -> 60 bytes (maximum)

So you **never parse the options to skip them**. You just jump `IHL * 4` bytes and you're at the TCP/UDP header.

**TCP**: same idea. The first 20 bytes are always there, plus 0 to 40 bytes of options. Byte 12 holds the **Data Offset** (top 4 bits) = header length in 32-bit words -> `tcp_header_len = (pkt[12] >> 4) * 4`.

### Summary: for each layer, read only 2 things

You don't need *all* the fields. To walk through the packet, at each layer you only need:

1. **How long is this header?** (fixed value, or the length field)
2. **What comes next?** (type / protocol / port)

| Layer    | How long is it?            | What comes next?            |
|----------|----------------------------|-----------------------------|
| Ethernet | 14 (fixed)                 | `h_proto` (bytes 12-13)     |
| IPv4     | `(byte0 & 0x0F) * 4`       | `protocol` (byte 9)         |
| TCP      | `(byte12 >> 4) * 4`        | dst/src port (bytes 0-3)    |
| UDP      | 8 (fixed)                  | dst/src port (bytes 0-3)    |

The other fields (TTL, checksum, flags, ...) you read **only if the exercise asks for them**.

---

## 5. Yes: use a `switch`, one per layer

Your idea of a `switch` is the normal way to do it. You get a chain of "parse this layer, then switch on its 'next' field":

```c
#include <arpa/inet.h>   /* ntohs */

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    const u_char *end = pkt_data + header->caplen;   /* first byte we are NOT allowed to read */
    const u_char *p   = pkt_data;

    /* ---------- Layer 2: Ethernet ---------- */
    if (p + 14 > end) return;
    struct ethhdr *eth = (struct ethhdr *) p;
    p += 14;

    switch (ntohs(eth->h_proto)) {
    case 0x0800:                       /* IPv4 */
        break;                         /* continue below */
    case 0x86DD:
        printf("IPv6 packet\n");
        return;
    case 0x0806:
        printf("ARP packet\n");
        return;
    default:
        printf("Other EtherType 0x%04x\n", ntohs(eth->h_proto));
        return;
    }

    /* ---------- Layer 3: IPv4 ---------- */
    if (p + 20 > end) return;                    /* minimum IP header */
    int ip_hlen = (p[0] & 0x0F) * 4;             /* IHL * 4 */
    if (ip_hlen < 20 || p + ip_hlen > end) return;
    u_int8_t proto = p[9];                       /* Protocol field */
    p += ip_hlen;                                /* skip IP header + options */

    /* ---------- Layer 4 ---------- */
    switch (proto) {
    case 6: {                                    /* TCP */
        if (p + 20 > end) return;
        u_int16_t sport = ntohs(*(u_int16_t *)(p + 0));
        u_int16_t dport = ntohs(*(u_int16_t *)(p + 2));
        int tcp_hlen = (p[12] >> 4) * 4;
        if (tcp_hlen < 20 || p + tcp_hlen > end) return;
        p += tcp_hlen;

        int payload_len = end - p;               /* bytes of application data */
        printf("TCP %u -> %u, payload %d bytes\n", sport, dport, payload_len);

        /* ---------- Layer 7: HTTP ---------- */
        if ((dport == 80 || sport == 80) && payload_len > 0) {
            /* p now points to "GET / HTTP/1.1\r\n..." or "HTTP/1.1 200 OK..." */
        }
        break;
    }
    case 17: {                                   /* UDP */
        if (p + 8 > end) return;
        u_int16_t sport = ntohs(*(u_int16_t *)(p + 0));
        u_int16_t dport = ntohs(*(u_int16_t *)(p + 2));
        printf("UDP %u -> %u\n", sport, dport);
        break;
    }
    case 1:
        printf("ICMP\n");
        break;
    default:
        printf("Other IP protocol %u\n", proto);
    }
}
```

Things to notice:

- `end = pkt_data + caplen` is computed **once**. Before reading each header we check `p + size > end`. That's how you stay inside the boundaries from `buffer-boundaries.png`.
- `p` moves forward layer by layer: `+14`, then `+ip_hlen`, then `+tcp_hlen`. After the last step, `p` points to the HTTP text.
- Each `switch` only looks at **one** field: the "what comes next" field of the current layer.
- Port 80 = HTTP is only a **convention**. The port tells you what the application *probably* is. To be sure, you check the payload (does it start with `GET `, `POST `, `HTTP/`...?).
