#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define OSUTAMII 100000

struct route_table_entry *rtable;
int rtable_len;
struct arp_entry arp_table[OSUTAMII];

typedef struct q_struct {
	queue q;
	int size;
}q_struct;

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

	rtable_len = read_rtable(argv[1], rtable);

	int arp_table_len = 0;
	
	q_struct *q_struct = malloc(sizeof(q_struct));
	q_struct->size = 0;
	q_struct->q = queue_create();


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

			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

			if(ntohs(arp_hdr->op) == 1) { // ARP Request

				uint32_t ip_current;
				inet_pton(AF_INET, get_interface_ip(interface), &ip_current);
				printf("REQUEST\n");

				if(ntohl(ip_current) != ntohl(arp_hdr->tpa)) { // daca nu e pentru mine, trimit mai departe
					printf("Not for me\n");

					continue;
				}

				afisare(ntohl(ip_current));

				arp_hdr->op = htons(2); // il fac reply

				uint32_t temp = arp_hdr->spa;
				arp_hdr->spa = arp_hdr->tpa;
				arp_hdr->tpa = temp;

				afisare(ntohl(arp_hdr->tpa));

				memcpy(arp_hdr->tha, arp_hdr->sha, 6); // interschimb mac-urile
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6); // interschimb mac-urile

				get_interface_mac(interface, arp_hdr->sha); // pun mac-ul meu in arp
				get_interface_mac(interface, eth_hdr->ether_shost); // pun mac-ul meu in eth

				printf("Got ARP request, sending reply\n");					
				send_to_link(interface, buf, len); // trimit
		
			} else if(ntohs(arp_hdr->op) == 2) { // ARP Reply

				printf("REPLY\n");
				int found = 0;

				uint32_t reply = ntohl(arp_hdr->spa);

				for (int i = 0; i < arp_table_len; i++) { // caut in tabela arp
					if (arp_table[i].ip == reply && !memcmp(arp_table[i].mac, arp_hdr->sha, 6)) {
						found = 1;
						break;
					}
				}


				if(!found) {
					printf("Arp entry not found\n");

					arp_table[arp_table_len].ip = arp_hdr->spa; // se adauga in tabela intrarea curenta
					memcpy(arp_table[arp_table_len].mac, eth_hdr->ether_shost, 6);
					++arp_table_len;

					printf("Added arp entry:\n");

					if(queue_empty(q_struct->q)) { // in cazul in care nu exista nimic in coada, se trece mai departe
						continue;
					}

					char* elem = queue_deq(q_struct->q); // scot elementul din coada
					--q_struct->size;
					struct ether_header *eth = (struct ether_header *) elem;
					struct iphdr *ip_coada = (struct iphdr *) (elem + sizeof(struct ether_header));

					struct route_table_entry *next = get_best_route(ntohl(ip_coada->daddr));
					if(!next) {
						printf("No route\n");
						continue;
					}

					uint8_t mac_sursa[8];
					get_interface_mac(next->interface, mac_sursa);
					memcpy(eth->ether_shost, mac_sursa, 6); // pun macul sursa in headerul eth
					memcpy(eth->ether_dhost, arp_hdr->sha, 6); // pun macul destinatie in headerul eth

					printf("Sending reply\n");
					send_to_link(next->interface, elem, len); // trimit pachetul
					continue;
				}
			}

			// continue;
			
		} else if(ntohs(eth_hdr->ether_type) == 0x0800) { // IPV4

			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
			
			uint32_t ip_current;
			inet_pton(AF_INET, get_interface_ip(interface), &ip_current);

			if(ntohl(ip_current) == ntohl(ip_hdr->daddr)) { // ICMP
				printf("ICMP\n");
				struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
				struct iphdr *ip_hdr_icmp = malloc(sizeof(struct iphdr));
				struct ether_header *eth_hdr_icmp = malloc(sizeof(struct ether_header));

				// ICMP HEADER
				icmp_hdr->type = 0; // 0 - echo, 3 - ruta, 11 - ttl
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;

				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr))); // calculez checksum

				memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr)); // copiez ip_hdr in ip_hdr_icmp
				uint32_t temp = ip_hdr_icmp->saddr;
				ip_hdr_icmp->saddr = ip_hdr_icmp->daddr;
				ip_hdr_icmp->daddr = temp;

				ip_hdr_icmp->protocol = 1; // ICMP
				ip_hdr_icmp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

				memcpy(eth_hdr_icmp, eth_hdr, sizeof(struct ether_header)); // copiez eth_hdr in eth_hdr_icmp
				for(int i = 0; i < 6; ++i) {
					uint8_t temp = eth_hdr_icmp->ether_shost[i];
					eth_hdr_icmp->ether_shost[i] = eth_hdr_icmp->ether_dhost[i];
					eth_hdr_icmp->ether_dhost[i] = temp;
				}

				char *buf_icmp = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				memcpy(buf_icmp, eth_hdr_icmp, sizeof(struct ether_header));
				memcpy(buf_icmp + sizeof(struct ether_header), ip_hdr_icmp, sizeof(struct iphdr));
				memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
				// memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));

				send_to_link(interface, buf_icmp, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				continue;
			}

			uint16_t check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if(!(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)) == check)) { // verific checksum
				printf("Checksum Diferit\n");
				continue;
			}

			if (ip_hdr->ttl <= 1) { // verific ttl
				printf("Bad TTL\n");
				struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
				struct iphdr *ip_hdr_icmp = malloc(sizeof(struct iphdr));
				struct ether_header *eth_hdr_icmp = malloc(sizeof(struct ether_header));

				// ICMP HEADER
				icmp_hdr->type = 11; // 0 - echo, 3 - ruta, 11 - ttl
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;

				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr))); // calculez checksum

				memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr)); // copiez ip_hdr in ip_hdr_icmp
				uint32_t temp = ip_hdr_icmp->saddr;
				ip_hdr_icmp->saddr = ip_hdr_icmp->daddr;
				ip_hdr_icmp->daddr = temp;

				ip_hdr_icmp->protocol = 1; // ICMP
				ip_hdr_icmp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

				memcpy(eth_hdr_icmp, eth_hdr, sizeof(struct ether_header)); // copiez eth_hdr in eth_hdr_icmp
				for(int i = 0; i < 6; ++i) {
					uint8_t temp = eth_hdr_icmp->ether_shost[i];
					eth_hdr_icmp->ether_shost[i] = eth_hdr_icmp->ether_dhost[i];
					eth_hdr_icmp->ether_dhost[i] = temp;
				}

				char *buf_icmp = malloc(sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr));
				memcpy(buf_icmp, eth_hdr_icmp, sizeof(struct ether_header));
				memcpy(buf_icmp + sizeof(struct ether_header), ip_hdr_icmp, sizeof(struct iphdr));
				memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
				memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));

				send_to_link(interface, buf_icmp, sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr));
				
				continue;
			}
			ip_hdr->ttl -= 1; // scad ttl pt pasul curent
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))); // recalculez checksum

			// Ruta urmatoare
			uint32_t ip_dest = ntohl(ip_hdr->daddr);
			struct route_table_entry *next = get_best_route(ip_dest);
			
			if(!next){ // verific existenta rutei
				printf("Route not found\n");
				struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
				struct iphdr *ip_hdr_icmp = malloc(sizeof(struct iphdr));
				struct ether_header *eth_hdr_icmp = malloc(sizeof(struct ether_header));

				// ICMP HEADER
				icmp_hdr->type = 3; // 0 - echo, 3 - ruta, 11 - ttl
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;

				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr))); // calculez checksum

				memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr)); // copiez ip_hdr in ip_hdr_icmp
				uint32_t temp = ip_hdr_icmp->saddr;
				ip_hdr_icmp->saddr = ip_hdr_icmp->daddr;
				ip_hdr_icmp->daddr = temp;

				ip_hdr_icmp->protocol = 1; // ICMP
				ip_hdr_icmp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

				memcpy(eth_hdr_icmp, eth_hdr, sizeof(struct ether_header)); // copiez eth_hdr in eth_hdr_icmp
				for(int i = 0; i < 6; ++i) {
					uint8_t temp = eth_hdr_icmp->ether_shost[i];
					eth_hdr_icmp->ether_shost[i] = eth_hdr_icmp->ether_dhost[i];
					eth_hdr_icmp->ether_dhost[i] = temp;
				}

				char *buf_icmp = malloc(sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr));
				memcpy(buf_icmp, eth_hdr_icmp, sizeof(struct ether_header));
				memcpy(buf_icmp + sizeof(struct ether_header), ip_hdr_icmp, sizeof(struct iphdr));
				memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
				memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));

				send_to_link(interface, buf_icmp, sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr));
			
				continue;
			}

			struct arp_entry *arp_cache = NULL;

			for(int i = 0; i < arp_table_len; i++) {
				if(ntohl(next->next_hop) == ntohl(arp_table[i].ip)) {
					arp_cache = &arp_table[i];
					printf("Found ip in arp table\n");
					break;
				}
			}

			if(!arp_cache) { // in cazul in care nu exista ip ul cautat nu exista in arp cache, generez un request
				char *temp = malloc(sizeof(char) * MAX_PACKET_LEN);
				memcpy(temp, buf, len);
				queue_enq(q_struct->q, temp);
				++q_struct->size;

				char *request = malloc(sizeof(char) * MAX_PACKET_LEN);
				struct ether_header *eth_request = (struct ether_header*) request; // intai headerul ethernet
				eth_request->ether_type = htons(0x0806);  // arp
				for(int i = 0; i < 6; ++i) { // broadcast
					eth_request->ether_dhost[i] = 0xFF;
				}

				uint8_t mac[6];
				get_interface_mac(next->interface, mac);
				memcpy(eth_request->ether_shost, mac, 6);

				struct arp_header *arp_request = (struct arp_header *) (request + sizeof(struct ether_header));

				arp_request->htype = htons(1);
				arp_request->ptype = htons(0x0800);
				arp_request->hlen = 6;
				arp_request->plen = 4;
				arp_request->op = ntohs(1);

				get_interface_mac(next->interface, arp_request->sha);
				for(int i = 0; i < 6; ++i) {
					arp_request->tha[i] = 0x00;
				}

				arp_request->tpa = next->next_hop; // scoate poate
				inet_pton(AF_INET, get_interface_ip(next->interface), &arp_request->spa);

				send_to_link(next->interface, (char*)eth_request, sizeof(struct ether_header) + sizeof(struct arp_header));
				continue;
			}

			uint8_t new_mac[6];
			get_interface_mac(interface, new_mac);

			memcpy(eth_hdr->ether_shost, new_mac, 6);

			send_to_link(next->interface, buf, len);			

		}


	}

}

