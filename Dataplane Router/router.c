#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
struct pkt {
	char buf[1600];
	int len;
};

struct route_table_entry *longestPrefixMatchHelper(uint32_t ip, int left, int right, struct route_table_entry *route_table) {
    if (left > right)
        return NULL;
    int mid = left + (right - left) / 2;
    if (route_table[mid].prefix == (ip & route_table[mid].mask)) {
        struct route_table_entry *next_match = longestPrefixMatchHelper(ip, mid + 1, right, route_table);

        return (next_match != NULL) ? next_match : &route_table[mid];

    } else if (ntohl(route_table[mid].prefix) < ntohl(ip)) {
        return longestPrefixMatchHelper(ip, mid + 1, right, route_table);
    } else {
        return longestPrefixMatchHelper(ip, left, mid - 1, route_table);
    }
}

struct route_table_entry *longestPrefixMatch(uint32_t ip, int rt_len, struct route_table_entry *route_table) {
    return longestPrefixMatchHelper(ip, 0, rt_len - 1, route_table);
}

uint8_t *arp_entry_function(uint32_t ip, int arp_len, struct arp_table_entry *arp_table) {
    for (int i = 0; i < arp_len; i++) {
        if (memcmp(&arp_table[i].ip, &ip, sizeof(ip)) == 0) {
            return arp_table[i].mac;
        }
    }
    return NULL;
}
int qsortCompareHelpher(const void *a, const void *b) {
    unsigned int aPrefix = ntohl(((const struct route_table_entry *)a)->prefix);
    unsigned int aMask = ntohl(((const struct route_table_entry *)a)->mask);

    unsigned int bPrefix = ntohl(((const struct route_table_entry *)b)->prefix);
    unsigned int bMask = ntohl(((const struct route_table_entry *)b)->mask);

    if (aPrefix != bPrefix) {
        return (aPrefix > bPrefix) ? 1 : -1;
    } else {
        return (aMask > bMask) ? 1 : ((aMask < bMask) ? -1 : 0);
    }
}



int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);
	struct route_table_entry *route_table = (struct route_table_entry *)calloc(70000, 16);
	int router_len = read_rtable (argv[1],route_table);

	struct arp_table_entry *arp_table = (struct arp_table_entry *)calloc(6 , 10);
	int len_arp = parse_arp_table ("arp_table.txt",arp_table);

	int arp_table_entry_actual = 0; 
	queue pkt_queue = queue_create();

	qsort(route_table, router_len, 16, qsortCompareHelpher);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + 14);

            if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0)
                continue; 
            
			uint32_t copy_dest = ip_hdr->daddr;
			uint16_t checksum_before = ip_hdr->check;

			char buf_bytes[8];
			size_t offset = 14 + sizeof(struct iphdr);
			size_t offset2 = sizeof(struct icmphdr) + sizeof(struct iphdr);
			memcpy(buf_bytes, buf + offset, 8);
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + offset);
			uint8_t *icmp_data = (uint8_t *)icmp_hdr + sizeof(struct icmphdr);


			if(ip_hdr->ttl <= 1) {
				icmp_hdr->type = 11;
				icmp_hdr->code = 0;

				struct iphdr *ip_hdr_original = (struct iphdr *)(buf + 14);

				memcpy(icmp_data, ip_hdr_original, sizeof(struct iphdr));
				memcpy(icmp_data + sizeof(struct iphdr), buf_bytes, 8);

				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, offset2 + 8));

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->ttl = 64;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + offset2 + 8);
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				size_t offset_len = offset + offset2 + 8;

                send_to_link(interface, buf, offset_len);
			}else if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
						if (icmp_hdr->type == 8) {
						icmp_hdr->type = 0;
						icmp_hdr->code = 0;

						icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - offset));

						ip_hdr->daddr = ip_hdr->saddr;
						ip_hdr->saddr = copy_dest;

						ip_hdr->ttl = 64;

						ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

						memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
						get_interface_mac(interface, eth_hdr->ether_shost);

						send_to_link(interface, buf, len);
						}
				} else {
			ip_hdr->ttl--;
			ip_hdr->check = ~(~checksum_before + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)(ip_hdr->ttl)) - 1;
			struct route_table_entry *LPMroute = longestPrefixMatch(ip_hdr->daddr, router_len, route_table);
			if (LPMroute == NULL) {
				icmp_hdr->type = 3;
				icmp_hdr->code = 0;

				struct iphdr *iphrd_use = (struct iphdr *)(buf + 14);

				memcpy(icmp_data, iphrd_use, sizeof(struct iphdr));
				memcpy(icmp_data + sizeof(struct iphdr), buf_bytes, 8);

				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, offset2 + 8));

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = copy_dest;
				ip_hdr->ttl = 64;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + offset2 + 8);
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				size_t offset_len = offset + offset2 + 8;

				send_to_link(interface, buf, offset_len);
				} else if ( arp_entry_function(LPMroute->next_hop, len_arp, arp_table) == NULL) {
				struct pkt *new_pkt = (struct pkt *)calloc(1, 1604);

				memcpy(new_pkt->buf, buf, len);
				new_pkt->len = len;

				queue_enq(pkt_queue, new_pkt);
				struct arp_header set_arp_H;

				set_arp_H.htype = htons(1);
				set_arp_H.ptype = htons(0x0800);

				set_arp_H.op = htons(1);
				
				set_arp_H.hlen = 6;
				set_arp_H.plen = 4;
				eth_hdr->ether_type = htons(2);

				get_interface_mac(LPMroute->interface, eth_hdr->ether_shost);
				get_interface_mac(LPMroute->interface, set_arp_H.sha);
				set_arp_H.spa = inet_addr(get_interface_ip(LPMroute->interface));

				memcpy(eth_hdr->ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(eth_hdr->ether_dhost));
				memcpy(set_arp_H.tha, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
				set_arp_H.tpa = LPMroute->next_hop;
								
				struct pkt arp;

				bzero(arp.buf, 1600);
				memcpy(arp.buf, eth_hdr, 14);
				memcpy(arp.buf + 14, &set_arp_H, 28);

				send_to_link(LPMroute->interface, arp.buf, 14 + 28);
			} else {

			uint8_t *new_mac = arp_entry_function(LPMroute->next_hop, len_arp, arp_table);
			memcpy(eth_hdr->ether_dhost, new_mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(LPMroute->interface, eth_hdr->ether_shost);
			send_to_link(LPMroute->interface, buf, len);

			}
			}

		} else if (ntohs(eth_hdr->ether_type) == 0x0806) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + 14);

			if (ntohs(arp_hdr->op) == 1) {
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				eth_hdr->ether_type = htons(0x0806);

				arp_hdr->htype = htons(1);
				arp_hdr->ptype = htons(0x0800);
				arp_hdr->op = htons(2);
				arp_hdr->hlen = 6;
				arp_hdr->plen = 4;

				memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
				memcpy(arp_hdr->tha, eth_hdr->ether_dhost, 6);

				arp_hdr->spa ^= arp_hdr->tpa;
				arp_hdr->tpa ^= arp_hdr->spa;
				arp_hdr->spa ^= arp_hdr->tpa;


				send_to_link(interface, buf, len);
			} else if (ntohs(arp_hdr->op) == 2) {
				if (inet_addr(get_interface_ip(interface)) != arp_hdr->tpa) {
					struct route_table_entry *LPMroute = longestPrefixMatch(arp_hdr->tpa, router_len, route_table);
					send_to_link(LPMroute->interface, buf, len);
				}else{
				if (arp_entry_function(arp_hdr->spa, arp_table_entry_actual + 1, arp_table) == NULL) {
					memcpy(arp_table[arp_table_entry_actual].mac, arp_hdr->sha, sizeof(arp_table[arp_table_entry_actual].mac));
					arp_table[arp_table_entry_actual].ip = arp_hdr->spa;
					arp_table_entry_actual++;
				}
				if (arp_table_entry_actual == len_arp) {

    				len_arp *= 2;
   					struct arp_table_entry *new_arp_table = (struct arp_table_entry *)malloc(len_arp * 10);
    				memcpy(new_arp_table, arp_table, arp_table_entry_actual * 10);
    				free(arp_table);
   					arp_table = new_arp_table;
					}
				
				while (1) {
					if (queue_empty(pkt_queue)) {
						break;
					}

					struct pkt *pkt = queue_deq(pkt_queue);
					struct ether_header *eth_pkt = (struct ether_header *)pkt->buf;
					struct iphdr *ip_pkt = (struct iphdr *)(pkt->buf + 14);
					struct route_table_entry *LPMroute = longestPrefixMatch(ip_pkt->daddr, router_len, route_table);

					uint8_t *mac = arp_entry_function(LPMroute->next_hop, arp_table_entry_actual + 1, arp_table);
					if (mac != NULL) {
						memcpy(eth_pkt->ether_dhost, mac, sizeof(eth_hdr->ether_dhost));
						send_to_link(LPMroute->interface, pkt->buf, pkt->len);
						free(pkt);
					} else {
						queue_enq(pkt_queue, pkt);
					}
				}
				}

			}
		}
		}
	}