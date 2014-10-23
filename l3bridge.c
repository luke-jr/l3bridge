#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
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
	LBP_ETHERNET,
	LBP_IPV4,
	LBP_IPV6,
};

struct protocol_info {
	const char *name;
	int addrsz;
} protocol_info[] = {
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
void set_routing_entry(const enum protocol redtype, const void * const red, struct if_cfg * const ifcfg, const enum protocol renhtype, const void * const renh)
{
	uint8_t fullred[redsz_max];
	size_t fullredsz;
	const size_t renhsz = protocol_info[renhtype].addrsz;
	
	struct routing_entry *re = get_route_(redtype, red, fullred, &fullredsz);
	if ((!re) || protocol_info[re->renhtype].addrsz < renhsz)
	{
		if (re)
		{
			// Can't just realloc without HASH_DEL in case it's moved
			HASH_DEL(routes, re);
			free(re);
		}
		const size_t totsz = sizeof(*re) + renhsz + fullredsz;
		re = malloc(totsz);
		HASH_ADD_KEYPTR(hh, routes, fullred, fullredsz, re);
	}
	
	re->ifcfg = ifcfg;
	re->renhtype = renhtype;
	memcpy(&re->xdata[0], renh, renhsz);
	
	// NOTE: In theory, we can skip this for cases where renhsz is a perfect match for the old renh size, but NOT if the new size is smaller!
	memcpy(&re->xdata[renhsz], fullred, fullredsz);
}

struct pktinfo {
	uint8_t *buf;
	size_t bufsz;
	struct sockaddr_ll *from;
	struct if_cfg *ifcfg;
};

enum l3p_nonether {
	L3P_STP = 0x10000,
};

static
void l3_ipv6(struct pktinfo * const pi, const uint8_t * const buf)
{
	if (buf[2] == 0x3a)
	{
		// ICMPv6
		const uint8_t * const icmpv6 = &buf[40];
		switch (icmpv6[0])
		{
			case 136:  // Neighbor Advertisement
			{
				const uint8_t * const v6addr = &icmpv6[8];
				if (icmpv6[0x18] == 2 && icmpv6[0x19] == 1 && pi->from->sll_hatype == ARPHRD_ETHER)
				{
					const uint8_t * const macaddr = &icmpv6[0x1a];
					set_routing_entry(LBP_IPV6, v6addr, pi->ifcfg, LBP_ETHERNET, macaddr);
				}
			}
		}
	}
	
	if (!buf[3])
	{
		fprintf(stderr, "Discarding IPv6 packet reaching its hop limit\n");
		return;
	}
	
	
}

static
void l3(struct pktinfo * const pi, const uint32_t l3p, const uint8_t * const buf)
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
void l2_ether(struct pktinfo * const pi, const uint8_t * const buf)
{
	uint32_t l3p;
	if (!memcmp(buf, "\x01\x80\xc2\0\0\0", 6))
		l3p = L3P_STP;
	else
		l3p = upk_u16be(buf, 0xc);
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