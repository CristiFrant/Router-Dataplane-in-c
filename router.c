#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include "string.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define ICMP_BUF_LEN sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8


typedef struct route_table_entry rEntry;
/* Routing table */
struct route_table_entry *rtable;
unsigned int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
unsigned int arp_table_len;

/* Packet waiting to get the target mac address */
typedef struct waiting_packet {
	size_t len;
	char *copied_buf;
	uint32_t hop_ip; 
} waiting_packet;

/*
 Compare function used to sort the rtable
*/
int cmpfunc (const void * a, const void * b) {
	const rEntry *r1 = (rEntry*)a;
	const rEntry *r2 = (rEntry*)b;
		
	if (r1->prefix > r2->prefix) {
		return -1;
	} else if (r1->prefix < r2->prefix) {
		return 1;
	} else if (r1->mask > r2->mask) {
		return -1;
	} else {
		return 1;
	}
}

/*
 Search for the LPM of the given ip_dest, uses binary search on a sorted rtable
*/
rEntry *get_best_route(uint32_t ip_dest, uint32_t l, uint32_t r) {
	if (l == r) {
		if ((rtable[l].mask & ip_dest) == rtable[l].prefix) {
			return &rtable[l];
		}
		return NULL;
	}
	uint32_t mid = (l + r) / 2;
	if ((rtable[mid].mask & ip_dest) == rtable[mid].prefix) {
		// It is possible that there are better matches. Since the rtable is
		// sorted in decreasing order, if there is a longer prefix, it will always
		// be on the left
		rEntry *betterMatch = get_best_route(ip_dest, l, mid - 1);
		if (betterMatch == NULL) {
			return &rtable[mid];
		} else {
			return betterMatch;
		}
	}
	if ((rtable[mid].mask & ip_dest) > rtable[mid].prefix) {
		// If the prefix is smaller thant the ip, search on the left
		return get_best_route(ip_dest, l, mid - 1);
	}
	// else search on the right
	return get_best_route(ip_dest, mid + 1, r);
}

/*
 Returns a pointer to the table entry for the mac address, or NULL if there
 is no matching entry.
*/
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	
	for (unsigned int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	
	return NULL;
}


/*
 Generate an icmp protocol packet to send back to the sender address
*/
size_t generate_icmp_packet(char *buf, uint8_t type, uint8_t code,
	char* lost_packet, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	// Go to the end of the ethernet header
	struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + 1);

	// Generate a new ip header for to encapsulate the icmp
	memcpy(eth_hdr, lost_packet, sizeof(struct ether_header));
	memcpy(ip_hdr, lost_packet + sizeof(struct ether_header), sizeof(struct iphdr));
	ip_hdr->daddr = ip_hdr->saddr;
	inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->saddr);
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
	ip_hdr->check = 0;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	icmp_hdr->checksum = 0;

	if (type == 3 || type == 11) {
		// If the icmp is an error type
		icmp_hdr->type = type;
		icmp_hdr->code = code;
		ip_hdr->tot_len = htons(ICMP_BUF_LEN - sizeof(struct ether_header));
		memcpy(icmp_hdr + 1,
			(lost_packet + sizeof(struct ether_header)), sizeof(struct iphdr) + 8);
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
			sizeof(struct icmphdr)));
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		return ICMP_BUF_LEN;
	} else {
		// The only other option in this homework is to be an echo type
		memcpy(icmp_hdr,
			lost_packet + sizeof(struct ether_header) + sizeof(struct iphdr),
			sizeof(struct icmphdr));
		icmp_hdr->type = 0; // echo reply
		ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));	
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
			sizeof(struct icmphdr)));
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		// Trim the size of the size of the error packet
		return ICMP_BUF_LEN - sizeof(struct iphdr) - 8; 
	}
}

/*
 Generate an arp request protocol for an interface that has an unknown mac address
*/
size_t generate_arp_request(char* buf, int interface, queue pack_queue,
	size_t len, uint32_t hop_ip) {
	uint32_t interface_ip;
	waiting_packet *pack = malloc(sizeof(waiting_packet));
	struct arp_header arp_hdr;
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);

	// Copy the buffer that has the packet in a waiting queue, along with the
	// size and the hop_ip, so it can be identified later
	pack->copied_buf = malloc(MAX_PACKET_LEN);
	memcpy(pack->copied_buf, buf, MAX_PACKET_LEN);
	pack->hop_ip = hop_ip;
	pack->len = len;
	queue_enq(pack_queue, pack);

	// Set all the arp fields for an arp request
	arp_hdr.htype = htons(HW_TYPE);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.hlen = MAC_LENGTH;
	arp_hdr.plen = IPV4_LENGTH;
	arp_hdr.op = htons(ARP_REQUEST);
	arp_hdr.spa = interface_ip;
	arp_hdr.tpa = hop_ip;
	get_interface_mac(interface, arp_hdr.sha);
    memset(arp_hdr.tha, 0x00, MAC_LENGTH);
	memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
	
	// Set the etherenet protocol to broadcast
	get_interface_mac(interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, MAC_LENGTH);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	printf("Sending ARP request\n");
	return sizeof(struct ether_header) + sizeof(struct arp_header);
}

/*
 Generate an arp reply protocol for a mac address request 
*/
size_t generate_arp_reply(char* buf, int interface) {
	uint32_t interface_ip;
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(eth_hdr + 1);
	inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);

	// If the target ip does not match the interface_ip, throw the packet
	if (interface_ip != arp_hdr->tpa) {
		return 0;
	}

	// Respond with an arp reply containing the mac address of the interface
	memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(uint8_t) * 6);
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = interface_ip;
	arp_hdr->op = htons(ARP_REPLY);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
	memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(uint8_t) * 6);
	printf("Sending ARP reply\n");
	return sizeof(struct ether_header) + sizeof(struct arp_header);
}

/*
 Process an arp reply and send all the packets that are wating in queue
*/
queue process_arp_reply(char *buf, int interface, queue pack_queue) {
	printf("Got ARP reply\n");
	struct arp_header *arp_hdr = 
		(struct arp_header *)(buf + sizeof(struct ether_header));

	// Create a new queue to put in the packets that do not have de ip of the reply
	queue new_queue = queue_create();
	// Add a new entry in the arp_table
	arp_table_len++;
	arp_table[arp_table_len].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(uint8_t) * 6);

	char temp_buf[MAX_PACKET_LEN];

	printf("Searching for waiting packets\n");
	while(!queue_empty(pack_queue)) {
		waiting_packet *pack = (waiting_packet *)queue_deq(pack_queue);
		if (pack->hop_ip == arp_hdr->spa) {
			// If the packet ip matches the arp ip address, copy the packet
			// to a temporary buffer and send it
			memcpy(temp_buf, pack->copied_buf, MAX_PACKET_LEN);
			struct ether_header *eth_hdr = (struct ether_header*) temp_buf;
			memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(uint8_t) * 6);
			free(pack->copied_buf);
			printf("Sending packet to: %x:%x:%x:%x:%x:%x\n",
				eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
				eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
				eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
			send_to_link(interface, temp_buf, pack->len);
			free(pack);
		} else {
			// Add it back to a new queue, if the ip addresses do not match
			queue_enq(new_queue, pack);
		}
	}
	free(pack_queue);
	return new_queue;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	char icmpBuf[ICMP_BUF_LEN];


	// Do not modify this line
	init(argc - 2, argv + 2);


	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	arp_table_len = 0;

	/* Read the static routing table and the MAC table */
	rtable_len = (unsigned int) read_rtable(argv[1], rtable);
	printf("rtable len = %d\n", rtable_len);
	DIE(rtable_len == 0, "rtable");

	qsort(rtable, rtable_len, sizeof(rEntry), cmpfunc);

	queue pack_queue = queue_create();
	
	while (1) {
		int interface;
		uint32_t interfaceAddr;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		// As of now, only recieve ip packets
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			void *next_hdr = (eth_hdr + 1);
			if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
				if (((struct arp_header *) next_hdr)->op == htons(ARP_REQUEST)) {
					len = generate_arp_reply(buf, interface);
					if (len != 0) {
						send_to_link(interface, buf, len);
					}
				} else {
					if (((struct arp_header *) next_hdr)->op == htons(ARP_REPLY)) {
						pack_queue = process_arp_reply(buf, interface, pack_queue);
					}
				}
			}
			continue;
		}
		struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
			printf("Checksum failed\n");
			continue;
		}

		// Checks if the inerface ip address is the destinatation address
		inet_pton(AF_INET, get_interface_ip(interface), &interfaceAddr);
		if (interfaceAddr == ip_hdr->daddr) {
			if (ip_hdr->protocol == 1
				&& ((struct icmphdr *)(buf+ sizeof(struct ether_header)
				+ sizeof(struct iphdr)))->type == 8) {
				len = generate_icmp_packet(icmpBuf, 8, 0, buf, interface);
				send_to_link(interface, icmpBuf, len);
			}
			continue;
		}

		/* Check TTL > 1. Update TLL.  */
		if (ip_hdr->ttl > 1) {
			ip_hdr->ttl--;
		} else {
			printf("TTL exceeded\n");
			len = generate_icmp_packet(icmpBuf, 11, 0, buf, interface);
			send_to_link(interface, icmpBuf, len);
			continue;
		}
		
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		// Search the most specific route for the packet
		struct route_table_entry *next_hop =
			get_best_route(ip_hdr->daddr, 0, rtable_len - 1);
		if (next_hop == NULL) {
			printf("Route not found\n");
			len = generate_icmp_packet(icmpBuf, 3, 0, buf, interface);
			send_to_link(interface, icmpBuf, len);
			continue;
		}
		// Search for the mac destination that follows
		struct arp_table_entry *entry = get_arp_entry(next_hop->next_hop);
		if (entry == NULL) {
			printf("Mac not found\n");
			get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
			len = generate_arp_request(buf, next_hop->interface, pack_queue,
				len, next_hop->next_hop);
			send_to_link(next_hop->interface, buf, len);
			continue;
		}

		memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t) * 6);
		get_interface_mac(next_hop->interface, eth_hdr->ether_shost);

		printf("Sending packet to: %x:%x:%x:%x:%x:%x\n",
				eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
				eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
				eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		send_to_link(next_hop->interface, buf, len);
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */ 
	}
}

