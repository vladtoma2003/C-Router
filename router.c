#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define OSUTAMII 100000

struct route_table_entry *rtable;
int rtable_len;
struct arp_entry *arp_table;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *next = NULL;
	uint32_t best = 0;
	for (int i = 0; i < rtable_len; i++) { // longest prefix match
			if ((ntohl(rtable[i].mask) & ip_dest) == ntohl(rtable[i].prefix) && best < ntohl(rtable[i].mask)) {
				next = &rtable[i];
				best = ntohl(rtable[i].mask);
		}
	}
	
	return next;
}

void afisare(uint32_t addr) {
    printf("%d.%d.%d.%d\n", (addr>>24)&0x00ff, (addr>>16)&0x00ff,(addr>>8)&0x00ff,addr&0x00ff);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * OSUTAMII); // Tabela de rutare
	DIE(rtable == NULL, "rtable memory");

	arp_table = malloc(sizeof(struct arp_entry) * OSUTAMII);
	DIE(arp_table == NULL, "arptable memory");


	rtable_len = read_rtable(argv[1], rtable);
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);


	struct arp_entry *arp_cache;
	int arp_cache_len;
	

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");


		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if(ntohs(eth_hdr->ether_type) == 0x0806) { // ARP
			printf("ARP\n");
			printf("MAC ADDRESS:%d\n", ntohs(*eth_hdr->ether_dhost));

			// check if the destination ip address is in the arp table
			if(arp_table_len == 0) {
				printf("Nu exista arp table\n");
				// create arp table
				arp_cache = malloc(sizeof(struct arp_entry) * OSUTAMII);
				DIE(arp_cache == NULL, "arptable memory");

				arp_cache_len = 0;
				// add to queue the request
				continue;
			}
			
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			int position = -1;
			for(int i = 0; i <= arp_cache_len; i++) {
				if(arp_hdr->spa == arp_table[i].ip) {
					// arp_spa = arp_table[i].ip;
					position = i;
					printf("Am gasit ip ul in arp table\n");
					// send arp reply
					// send_to_link(interface, buf, len);
					continue;
				}
			}
			if(position == -1) {
				printf("Nu am gasit ip ul in arp table\n");
				// add to queue the request
				// send arp request
				// send_to_link(interface, buf, len);
				continue;
			}



			memcpy(arp_hdr->tha, arp_table[position].mac, 6);


			continue;
			
		} else if(ntohs(eth_hdr->ether_type) == 0x0800) { // IPV4

			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
			
			uint16_t check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if(!(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)) == check)) { // verific checksum
				// printf("Checksum Diferit\n");
				continue;
			}
			// printf("Checksum ok :)\n");

			if (ip_hdr->ttl < 1) { // verific ttl
				// send_to_link(interface, buf, len);
				continue;
			}
			ip_hdr->ttl -= 1; // scad ttl pt pasul curent
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))); // recalculez checksum

			// Ruta urmatoare
			uint32_t ip_dest = ntohl(ip_hdr->daddr);
			struct route_table_entry *next = get_best_route(ip_dest);
			// afisare(ntohl(ip_hdr->daddr));
			// afisare(ntohl(ip_hdr->saddr));
			// printf("next->prefix:");
			if(!next){ // verific existenta rutei
				printf("Nu exista ip ul LMAO\n");
				continue;
			}
			// afisare(ntohl(next->next_hop));

			
			printf("next:");
			// afisare(next->interface);

			uint8_t new_mac[6];
			get_interface_mac(interface, new_mac);

			memcpy(eth_hdr->ether_shost, new_mac, 6);

			send_to_link(next->interface, buf, len);			

		}


	}

}

