#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <uthash.h>

#include "util.h"


#define BUFSZ  0x1000

struct if_cfg {
	const char *ifname;
	bool enabled;
	
	UT_hash_handle hh;
};

enum protocol {
	LBP_NONE,
	LBP_ETHERNET,
	LBP_IPV4,
	LBP_IPV6,
};

struct protocol_info {
	const char *name;
	int addrsz;
} protocol_info[] = {
	{ "(none)"  ,    0, },
	{ "Ethernet",    6, },
	{ "IPv4"    ,    4, },
	{ "IPv6"    , 0x10, },
};

struct routing_entry {
	UT_hash_handle hh;
	
	struct if_cfg *ifcfg;
	enum protocol renhtype;
	uint8_t xdata[];
	// variant renh
	// enum protocol redtype;
	// variant red
};

static struct if_cfg *cfgs;
static struct routing_entry *routes;
static int ps;

static
struct if_cfg *ifcfg_from_ifindex(const unsigned int ifindex)
{
	static struct if_cfg invalid_ifcfg;
	invalid_ifcfg = (struct if_cfg){ .enabled = false, };
	char ifname_buf[IF_NAMESIZE];
	char *ifname = if_indextoname(ifindex, ifname_buf);
	if (!ifname)
		return &invalid_ifcfg;
	struct if_cfg *ifcfg;
	HASH_FIND_STR(cfgs, ifname, ifcfg);
	return ifcfg ?: &invalid_ifcfg;
}

static const size_t redsz_max = 0x10;

static
struct routing_entry *get_route_(const enum protocol redtype, const void * const red, uint8_t * const fullred, size_t * const fullredsz)
{
	const size_t redsz = protocol_info[redtype].addrsz;
	*fullredsz = sizeof(redtype) + redsz;
	memcpy(fullred, &redtype, sizeof(redtype));
	memcpy(&fullred[sizeof(redtype)], red, redsz);
	struct routing_entry *re;
	HASH_FIND(hh, routes, fullred, *fullredsz, re);
	return re;
}

static
struct routing_entry *get_route(const enum protocol redtype, const void * const red)
{
	uint8_t fullred[redsz_max];
	size_t fullredsz;
	return get_route_(redtype, red, fullred, &fullredsz);
}

static
int protocol_dest_str(char * const s, const size_t sz, const enum protocol proto, const uint8_t * const addr)
{
	const size_t addrsz = protocol_info[proto].addrsz;
	char hex[(addrsz * 2) + 1];
	bin2hex(hex, addr, addrsz);
	return snprintf(s, sz, "%s:%s", protocol_info[proto].name, hex);
}

static
// "PROTO:HEX via PROTO:HEX dev IFNAME"
int routing_entry_str(char *s, size_t sz, const struct routing_entry * const re)
{
	int rv = 0;
	const size_t renhsz = protocol_info[re->renhtype].addrsz;
	enum protocol redtype;
	memcpy(&redtype, &re->xdata[renhsz], sizeof(redtype));
	_SNP2(protocol_dest_str, redtype, &re->xdata[renhsz + sizeof(redtype)]);
	_SNP(" via ");
	_SNP2(protocol_dest_str, re->renhtype, re->xdata);
	_SNP(" dev %s", re->ifcfg->ifname);
	return rv;
}

static
void set_routing_entry(const enum protocol redtype, const void * const red, struct if_cfg * const ifcfg, const enum protocol renhtype, const void * const renh)
{
	uint8_t fullred[redsz_max];
	size_t fullredsz;
	char rstr[0x100];
	const size_t renhsz = protocol_info[renhtype].addrsz;
	
	struct routing_entry *re = get_route_(redtype, red, fullred, &fullredsz);
	if (re)
	{
		if (re->renhtype == renhtype && !memcmp(re->xdata, renh, renhsz))
			// Same route
			return;
		
		routing_entry_str(rstr, sizeof(rstr), re);
		fprintf(stderr, "Replacing route %s\n", rstr);
		HASH_DEL(routes, re);
		if (protocol_info[re->renhtype].addrsz < renhsz)
		{
			free(re);
			goto no_re;
		}
	}
	else
	{
no_re: ;
		const size_t totsz = sizeof(*re) + renhsz + fullredsz;
		re = malloc(totsz);
	}
	
	re->ifcfg = ifcfg;
	re->renhtype = renhtype;
	memcpy(&re->xdata[0], renh, renhsz);
	
	// NOTE: In theory, we can skip this for cases where renhsz is a perfect match for the old renh size, but NOT if the new size is smaller!
	memcpy(&re->xdata[renhsz], fullred, fullredsz);
	
	routing_entry_str(rstr, sizeof(rstr), re);
	fprintf(stderr, "Adding    route %s\n", rstr);
	HASH_ADD_KEYPTR(hh, routes, &re->xdata[renhsz], fullredsz, re);
}

struct pktinfo {
	uint8_t *buf;
	size_t bufsz;
	struct sockaddr_ll *from;
	struct if_cfg *ifcfg;
	enum protocol l2_proto;
	const void *l2_srcaddr;
};

enum l3p_nonether {
	L3P_STP = 0x10000,
};

static
bool get_hwaddr(void * const buf, const size_t bufsz, const struct if_cfg * const ifcfg, const unsigned short fam)
{
	if (strlen(ifcfg->ifname) >= IFNAMSIZ)
	{
		fprintf(stderr, "Interface name '%s' too long!\n", ifcfg->ifname);
		return false;
	}
	
	struct ifreq ifr;
	strcpy(ifr.ifr_name, ifcfg->ifname);
	if (ioctl(ps, SIOCGIFHWADDR, &ifr) == -1 || ifr.ifr_hwaddr.sa_family != fam)
	{
		fprintf(stderr, "Error getting hw address for '%s'\n", ifcfg->ifname);
		return false;
	}
	
	memcpy(buf, ifr.ifr_hwaddr.sa_data, bufsz);
	return true;
}

static
bool get_linkaddr(void * const out, const struct if_cfg * const ifcfg, const int domain, const int addrsz)
{
	const int nls = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (nls < 0)
	{
		fprintf(stderr, "Can't open netlink\n");
		return false;
	}
	
	const int ifindex = if_nametoindex(ifcfg->ifname);
	if (!ifindex)
		return false;
	
	struct {
		struct nlmsghdr hdr;
		struct ifaddrmsg msg;
		struct rtattr rt __attribute__ ((aligned(NLMSG_ALIGNTO)));
		uint8_t data[0x10];
	} req = {
		.hdr = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(req.msg)),
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
			.nlmsg_type = RTM_GETADDR,
		},
		.msg = {
			.ifa_family = domain,
			.ifa_index = ifindex,
		},
		.rt = {
			.rta_len = RTA_LENGTH(addrsz),
		},
	};
	if (addrsz > sizeof(req.data))
	{
		fprintf(stderr, "addrsz(%d) > sizeof(req.data)\n", addrsz);
		return false;
	}
	
	if (send(nls, &req, req.hdr.nlmsg_len, 0) < 0)
	{
err:
		fprintf(stderr, "Error in netlink communication\n");
		close(nls);
		return false;
	}
	
	char buf[0x4000];
	struct iovec iov = {
		.iov_base = buf,
	};
	struct sockaddr_nl nladdr;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	bool found = false;
	bool done = false;
	while (!done)
	{
		iov.iov_len = sizeof(buf);
		int status = recvmsg(nls, &msg, 0);
		if (status <= 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;
			goto err;
		}
		
		for (struct nlmsghdr *hdr = (void*)buf; NLMSG_OK(hdr, status); hdr = NLMSG_NEXT(hdr, status))
		{
			if (hdr->nlmsg_type == NLMSG_DONE)
				done = true;
			if (hdr->nlmsg_type != 0x14 /* FIXME */)
				continue;
			
			struct ifaddrmsg * const msg = (void*)NLMSG_DATA(hdr);
			if (msg->ifa_family != domain || msg->ifa_index != ifindex)
				continue;
			int rtsz = IFA_PAYLOAD(hdr);
			
			for (struct rtattr *rt = (void*)IFA_RTA(msg); RTA_OK(rt, rtsz); rt = RTA_NEXT(rt, rtsz))
			{
				if (rt->rta_type != IFA_ADDRESS)
					continue;
				
				if (found)
				{
					// Check if we already have our idea address
					switch (domain)
					{
						case AF_INET6:
							if (upk_u16be(out, 0) == 0xfe80)
								goto skiprt;
							break;
						default:
							break;
					}
				}
				
				found = true;
				memcpy(out, RTA_DATA(rt), addrsz);
				
skiprt: ;
			}
		}
	}
	close(nls);
	return found;
}

static
bool route_l2_ether(const struct routing_entry * const re, const enum protocol proto, const uint8_t * const buf, const size_t bufsz)
{
	uint16_t nextproto;
	switch (proto)
	{
		case LBP_IPV6:
			nextproto = ETH_P_IPV6;
			break;
		default:
			fprintf(stderr, "Don't know how to put %s inside Ethernet\n", protocol_info[proto].name);
			return false;
	}
	
	nextproto = htons(nextproto);
	
	uint8_t fullpkt[14 + bufsz];
	memcpy(&fullpkt[  0], re->xdata, 6);
	if (!get_hwaddr(&fullpkt[6], 6, re->ifcfg, ARPHRD_ETHER))
		return false;
	memcpy(&fullpkt[0xc], &nextproto, 2);
	memcpy(&fullpkt[0xe], buf, bufsz);
	
	struct sockaddr_ll sa;
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = if_nametoindex(re->ifcfg->ifname);
	if (!sa.sll_ifindex)
	{
		fprintf(stderr, "Error finding outgoing interface '%s'\n", re->ifcfg->ifname);
		return false;
	}
	sa.sll_halen = 6;
	memcpy(sa.sll_addr, re->xdata, 6);
	
	if (sendto(ps, fullpkt, sizeof(fullpkt), 0, (void*)&sa, sizeof(sa)) != sizeof(fullpkt))
	{
		fprintf(stderr, "Error sending packet on '%s'\n", re->ifcfg->ifname);
		return false;
	}
	
	return true;
}

static
void icmpv6_checksum(void * const buf, const size_t sz)
{
	unsigned i;
	uint8_t *p = buf;
	uint32_t sum = 0;
	
	// Addresses
	for (i = 8; i < 40; i += 2)
		sum += upk_u16le(p, i);
	// ICMPv6 length
	sum += upk_u16le(p, 4);
	// Next header
	sum += (uint16_t)p[6] << 8;
	// ICMPv6 data
	sum += upk_u16le(p, 40);
	for (i = 44; i < sz; i += 2)
		sum += upk_u16le(p, i);
	
	sum += sum >> 0x10;
	sum = 0xffff & ~sum;
	
	pk_u16le(buf, 0x2a, sum);
}

static
void solicit_route_ipv6(const void * const destaddr)
{
	uint8_t ipv6pkt[0x48] = {
		0x60, 0, 0, 0, 0, 0x20, 0x3a, 0xff,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // source addr
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // dest addr
		// ICMPv6
		135,  // Neighbor Solicitation
		0,
		0,0,  // checksum
		0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // dest addr
		// ICMPv6 option
		1,  // type: source link-layer address
		1,  // length: 1-8 bytes
		0,0,0,0,0,0,  // link-layer address
	};
	struct {
		struct routing_entry re;
		uint8_t buf[6];
	} my_re = {
		.re = {
			.renhtype = LBP_ETHERNET,
		},
	};
	struct if_cfg *ifcfg, *ifcfgtmp;
	HASH_ITER(hh, cfgs, ifcfg, ifcfgtmp)
	{
		if (!get_hwaddr(&ipv6pkt[0x42], 6, ifcfg, ARPHRD_ETHER))
			continue;
		if (!get_linkaddr(&ipv6pkt[8], ifcfg, AF_INET6, 0x10))
			continue;
		memcpy(&ipv6pkt[0x18], destaddr, 0x10);
		memcpy(&ipv6pkt[0x30], destaddr, 0x10);
		icmpv6_checksum(ipv6pkt, sizeof(ipv6pkt));
		
		my_re.re.ifcfg = ifcfg;
		memset(my_re.buf, '\xff', 6);
		if (route_l2_ether(&my_re.re, LBP_IPV6, ipv6pkt, sizeof(ipv6pkt)))
		{
			char s[0x100];
			protocol_dest_str(s, sizeof(s), LBP_IPV6, destaddr);
			fprintf(stderr, "Solicited route for %s\n", s);
		}
	}
}

static
void solicit_route(const enum protocol proto, const void * const destaddr)
{
	switch (proto)
	{
		case LBP_IPV6:
			solicit_route_ipv6(destaddr);
			break;
		default:
		{
			char s[0x100];
			protocol_dest_str(s, sizeof(s), proto, destaddr);
			fprintf(stderr, "Don't know how to solicit route for %s\n", s);
		}
	}
}

static
void route_out(const enum protocol proto, const void * const destaddr, const uint8_t * const buf, const size_t bufsz)
{
	const struct routing_entry * const re = get_route(proto, destaddr);
	if (!re)
	{
		char s[0x100];
		protocol_dest_str(s, sizeof(s), proto, destaddr);
		fprintf(stderr, "Failed to get route for %s\n", s);
		solicit_route(proto, destaddr);
		return;
	}
	
	switch (re->renhtype)
	{
		case LBP_ETHERNET:
			route_l2_ether(re, proto, buf, bufsz);
			break;
		default:
		{
			char s[0x100];
			routing_entry_str(s, sizeof(s), re);
			fprintf(stderr, "Don't know how to route out for %s\n", s);
		}
	}
}

static
void this_layer_address(struct pktinfo * const pi, enum protocol proto, const void * const srcaddr, const void * const dstaddr)
{
	if (pi->l2_proto != LBP_NONE)
		return;
	
	pi->l2_proto = proto;
	pi->l2_srcaddr = srcaddr;
}

static
void l3_ipv6(struct pktinfo * const pi, uint8_t * const buf)
{
	const size_t bufsz = pi->bufsz - (buf - pi->buf);
	if (buf[6] == 0x3a)
	{
		// ICMPv6
		const uint8_t * const icmpv6 = &buf[40];
		switch (icmpv6[0])
		{
			case 136:  // Neighbor Advertisement
			{
				const uint8_t * const v6addr = &icmpv6[8];
#if 0
				// TODO: properly implement the option
				if (bufsz >= 0x18 && icmpv6[0x18] == 2 && icmpv6[0x19] == 1 && pi->from->sll_hatype == ARPHRD_ETHER)
				{
					const uint8_t * const macaddr = &icmpv6[0x1a];
					set_routing_entry(LBP_IPV6, v6addr, pi->ifcfg, LBP_ETHERNET, macaddr);
				}
#endif
				if (pi->l2_proto != LBP_NONE)
					set_routing_entry(LBP_IPV6, v6addr, pi->ifcfg, LBP_ETHERNET, pi->l2_srcaddr);
			}
		}
	}
	
	if (!buf[7])
	{
		fprintf(stderr, "Discarding IPv6 packet reaching its hop limit\n");
		return;
	}
	--buf[7];
	
	const uint8_t * const destaddr = &buf[0x18];
	route_out(LBP_IPV6, destaddr, buf, bufsz);
}

static
void l3(struct pktinfo * const pi, const uint32_t l3p, uint8_t * const buf)
{
#if 0
	struct if_cfg *other, *tmp;
	const size_t bufsz = pi->bufsz - (buf - pi->buf);
	HASH_ITER(hh, cfgs, other, tmp)
	{
		if (other == pi->ifcfg)
			continue;
		
		sendto(ps, buf, bufsz, 
	}
#endif
	
	switch (l3p)
	{
		case ETH_P_IPV6:
			l3_ipv6(pi, buf);
			break;
		case ETH_P_ARP:
		case ETH_P_IP:
		case L3P_STP:
			// TODO
			break;
		default:
			fprintf(stderr, "Unknown layer 3 header: %04lx\n", (unsigned long)l3p);
	}
}

static
void l2_ether(struct pktinfo * const pi, uint8_t * const buf)
{
	uint32_t l3p;
	if (!memcmp(buf, "\x01\x80\xc2\0\0\0", 6))
		l3p = L3P_STP;
	else
		l3p = upk_u16be(buf, 0xc);
	this_layer_address(pi, LBP_ETHERNET, &buf[6], &buf[0]);
	l3(pi, l3p, &buf[0xe]);
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; ++i)
	{
		struct if_cfg * const cfg = malloc(sizeof(*cfg));
		*cfg = (struct if_cfg){
			.enabled = true,
			.ifname = argv[i],
		};
		HASH_ADD_KEYPTR(hh, cfgs, cfg->ifname, strlen(cfg->ifname), cfg);
	}
	
	ps = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	assert(ps >= 0);
	uint8_t buf[BUFSZ];
	ssize_t r;
	struct sockaddr_ll safrom;
	socklen_t safrom_sz;
	struct pktinfo pi = {
		.buf = buf,
		.from = &safrom,
	};
	while (true)
	{
		safrom_sz = sizeof(safrom);
		r = recvfrom(ps, buf, sizeof(buf), MSG_TRUNC, (void*)&safrom, &safrom_sz);
		if (r > sizeof(buf))
		{
			fprintf(stderr, "Buffer overflow: %ld bytes\n", (long)r);
			continue;
		}
		if (r < 0)
		{
			fprintf(stderr, "Error on packet socket: %ld\n", (long)r);
			abort();
		}
		safrom.sll_protocol = ntohs(safrom.sll_protocol);
		pi.bufsz = r;
		pi.ifcfg = ifcfg_from_ifindex(safrom.sll_ifindex);
		pi.l2_proto = LBP_NONE;
// 		fprintf(stderr, "protocol=%04x if=%s(%d) hatype=%u pkttype=%u halen=%u len=%lu\n", safrom.sll_protocol, pi.ifcfg->ifname, safrom.sll_ifindex, safrom.sll_hatype, safrom.sll_pkttype, safrom.sll_halen, (unsigned long)r);
		if (!pi.ifcfg->enabled)
			continue;

		switch (safrom.sll_hatype)
		{
			case ARPHRD_ETHER:
				l2_ether(&pi, buf);
				break;
			default:
				fprintf(stderr, "Unknown layer 2 header: %02x\n", safrom.sll_hatype);
		}
	}
	return 0;
}