//Heitor Scalco Neto 
//Mestrado DCC - UFLA
//10/08/2015
//Compilar: gcc -o cap_module cap_module.c -lpcap
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
//#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

//Number of bytes to take of the payload.
#define NUM_BYTES_GET 5

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct cabecalho_ip {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	    unsigned int ip_hl:4;		/* header length */
	    unsigned int ip_v:4;		/* version */
	#endif
	#if __BYTE_ORDER == __BIG_ENDIAN
	    unsigned int ip_v:4;		/* version */
	    unsigned int ip_hl:4;		/* header length */
	#endif
	    u_int8_t ip_tos;			/* type of service */
	    u_short ip_len;				/* total length */
	    u_short ip_id;				/* identification */
	    u_short ip_off;				/* fragment offset field */
	#define	IP_RF 0x8000			/* reserved fragment flag */
	#define	IP_DF 0x4000			/* dont fragment flag */
	#define	IP_MF 0x2000			/* more fragments flag */
	#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */									
	    u_int8_t ip_ttl;			/* time to live */
	    u_int8_t ip_p;				/* protocol */
	    u_short ip_sum;				/* checksum */
	    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

#define IP_ISFRAG(cabecalho_ip)    (((cabecalho_ip)->ip_off & htons(IP_MF | IP_OFFMASK)) != 0)

/* TCP header */
typedef u_int tcp_seq;

struct cabecalho_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct cabecalho_udp {
	__extension__ union {
		struct {
			u_int16_t uh_sport;		/* source port */
			u_int16_t uh_dport;		/* destination port */
			u_int16_t uh_ulen;		/* udp length */
			u_int16_t uh_sum;		/* udp checksum */
		};

		struct {
			u_int16_t source;
			u_int16_t dest;
			u_int16_t len;
			u_int16_t check;
		};	
	};
};

struct cabecalho_icmp {
  u_int8_t type;			/* message type */
  u_int8_t code;			/* type sub-code */
  u_int16_t checksum;
  union {
    struct {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;					/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct {
      u_int16_t	__glibc_reserved;
      u_int16_t	mtu;
    } frag;					/* path mtu discovery */
  } un;
};

#define TIMESTAMP 8


char* preprocessing_int(char buffer[300], int campo, int add_virgula){
	char buffer2[200];	
	sprintf(buffer2, "%d", campo);
	strcat(buffer, buffer2);
	if (add_virgula == 1){
		strcat(buffer, ",");	
	}	
	return buffer;
}

char* print_hexa(const u_char *payload, int len, int offset){
	int i;	
	const u_char *ch;	
	char payload_final[300];
	memset(payload_final, 0, sizeof(payload_final));
	char *retorno = malloc(300);
	int buffer2;		

	ch = payload;
	for(i = 0; i < len; i++) {
		// printf("Hexa: %02x ", *ch);
		buffer2 = *ch;		
		// printf("  Decimal: %d\n", buffer2 );												
		preprocessing_int(payload_final, buffer2, 1);					
		ch++;		
	}	
	strcpy(retorno, payload_final);	

	return retorno;
}

char* get_payload_part(const u_char *payload, int len, int qtd_bytes){		
	int offset = 0;
	const u_char *ch = payload;
	char *payload_final;
	if (len <= 0)
		return;
	payload_final = print_hexa(ch, qtd_bytes, offset); //5 primeiros
	strcat(payload_final, print_hexa(ch = (ch + len-qtd_bytes), qtd_bytes, offset)); //5 últimos
	return payload_final;
}

void getBin(int num, char *str, int num_bits){
	*(str+5) = '\0';
	int mask = 0x80 << 1;
	while(mask >>= 1)
		*str++ = !!(mask & num) + '0';		
}


int bin_to_dec(int bin){
	int total = 0;
	int potenc = 1;
	while(bin > 0) {
		total += bin % 10 * potenc;
		bin = bin / 10;
		potenc = potenc * 2; 
	}
	return total;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	const struct sniff_ethernet *ethernet;	//CABEÇALHO ETHERNET
	const struct cabecalho_ip *ip;          //CABEÇALHO IP	
	struct cabecalho_tcp *tcp;            	//CABEÇALHO TCP
	struct cabecalho_udp *udp; 			  	//CABEÇALHO UDP	
	const struct cabecalho_icmp *icmp; 		//CABEÇALHO ICMP	
	const char *payload;              		//PAYLOAD DO PACOTE
	
	int size_ip=0, 
		size_tcp=0, 
		size_payload = 0, 
		i=0, 
		size_udp = 0,
		size_icmp = 0;	

	char str[10] = "0", aux_vector[2] = "0";	
	char buffer[200];	
	memset(buffer, 0, sizeof(buffer));
	
	//Ethernet	
	ethernet = (struct sniff_ethernet*)(packet);

	//IP		
	ip = (struct cabecalho_ip*)(packet + SIZE_ETHERNET);	
	size_ip = ip->ip_hl*4;

	if (size_ip < 20) {
		//printf("* Tamanho do cabeçalho IP inválido: %u bytes\n", size_ip);
		return;
	}	

	switch(ip->ip_p) {
		case IPPROTO_TCP: //TCP
			tcp = (struct cabecalho_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("* Cabeçalho TCP inválido: %u bytes\n", size_tcp);
				return;
			}					
			
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			if(tcp->th_urp == 0){
				tcp->th_urp = 0;
			} else {
				tcp->th_urp = 1;
			}						

			strcpy(buffer, "tcp,");					
			preprocessing_int(buffer, ip->ip_hl, 1);
			preprocessing_int(buffer,  ntohs(ip->ip_len), 1);
			preprocessing_int(buffer,  ntohs(ip->ip_id), 1);
								
			//strcat(buffer, "FLAGS IP:");
			getBin(ip->ip_off, str, 3);			
			strncpy(aux_vector, str, 3);		
			preprocessing_int(buffer,  bin_to_dec(atoi(aux_vector)), 1);					

			//strcat(buffer, "FRAG:");			
			preprocessing_int(buffer,  IP_ISFRAG(ip), 1); //Verificar resultado quando esta setado.

			preprocessing_int(buffer,  ip->ip_ttl, 1);
			preprocessing_int(buffer,  ntohs(tcp->th_sport), 1);
			preprocessing_int(buffer,  ntohs(tcp->th_dport), 1);
			
			//strcat(buffer, "FLAGS TCP: ");	
			preprocessing_int(buffer,  tcp->th_flags, 1);
			preprocessing_int(buffer,  ntohs(tcp->th_win), 1);
			preprocessing_int(buffer,  tcp->th_urp, 1);						
			//Deixa todos com o mesmo numero de colunas
			strcat(buffer, "0,0,0,0,");				


			if(size_payload > 0)	{
				strcat(buffer, get_payload_part(payload, size_payload, NUM_BYTES_GET)); //10 campos	
			} else {
				for(i=0; i<NUM_BYTES_GET*2;i++){
					strcat(buffer, "0,");	
				}				
			}			
			break;

		case IPPROTO_UDP: //UDP			
			udp = (struct cabecalho_udp*)(packet + size_ip  + SIZE_ETHERNET);
			size_udp =  sizeof(struct sniff_ethernet) + size_ip + sizeof udp;		

			strcpy(buffer, "udp,");
			preprocessing_int(buffer, ip->ip_hl, 1);
			preprocessing_int(buffer,  ntohs(ip->ip_len), 1);
			preprocessing_int(buffer,  ntohs(ip->ip_id), 1);
			getBin(ip->ip_off, str, 3);
			strncpy(aux_vector, str, 3);
			preprocessing_int(buffer,  bin_to_dec(atoi(aux_vector)), 1);
			preprocessing_int(buffer,  IP_ISFRAG(ip), 1); //Verificar resultado quando esta setado.
			preprocessing_int(buffer,  ip->ip_ttl, 1);
			preprocessing_int(buffer,  ntohs(udp->source), 1);
			preprocessing_int(buffer,  ntohs(udp->dest), 1);
			//Deixa todos com o mesmo numero de colunas
			strcat(buffer, "0,0,0,");				
			preprocessing_int(buffer,  ntohs(udp->len), 1);
			//Deixa todos com o mesmo numero de colunas
			strcat(buffer, "0,0,0,0,");

			payload = (u_char *)(packet + size_udp);
			size_payload = (header->len) - SIZE_ETHERNET - size_ip - sizeof udp;
			if(size_payload > 0){
				strcat(buffer, get_payload_part(payload, size_payload, NUM_BYTES_GET)); //10 campos
			} else {
				for(i=0; i<NUM_BYTES_GET*2;i++){
					strcat(buffer, "none,");	
				}				
			}						
			break;

		case IPPROTO_ICMP: //icmp
			icmp = (struct cabecalho_icmp*)(packet + size_ip  + SIZE_ETHERNET);
			size_icmp =  sizeof(struct sniff_ethernet) + size_ip + sizeof icmp;
			payload = (u_char *)(packet + size_icmp);			
			size_payload = (header->len) - SIZE_ETHERNET - size_ip - sizeof icmp;						

			strcpy(buffer, "icmp,");
			preprocessing_int(buffer, ip->ip_hl, 1);
			preprocessing_int(buffer,  ntohs(ip->ip_len), 1);
			preprocessing_int(buffer,  ntohs(ip->ip_id), 1);
			getBin(ip->ip_off, str, 3);
			strncpy(aux_vector, str, 3);
			preprocessing_int(buffer,  bin_to_dec(atoi(aux_vector)), 1);
			preprocessing_int(buffer,  IP_ISFRAG(ip), 1); //Verificar resultado quando esta setado.
			preprocessing_int(buffer,  ip->ip_ttl, 1);
			//Deixa todos com o mesmo numero de colunas
			strcat(buffer, "0,0,0,0,0,0,");

			//icmp
			preprocessing_int(buffer,   icmp->type, 1);
			preprocessing_int(buffer,   icmp->code, 1);
			preprocessing_int(buffer,   ntohs(icmp->un.echo.id), 1);
			preprocessing_int(buffer,   ntohs(icmp->un.echo.sequence), 1);
			// strcat(buffer, "PAYLOAD: ");			

			if(size_payload > 0){
				//Verificar se a base de dados desconta o timestamp nos dados.
				strcat(buffer, get_payload_part(payload, size_payload, NUM_BYTES_GET)); //10 campos
			} else {
				for(i=0; i<NUM_BYTES_GET*2;i++){
					strcat(buffer, "none,");	
				}				
			}	
			break;		
	
		default:
			printf("   Protocol: Unknown\n");
			return;
	}		

	printf("%s\n", buffer);										

	return;

}



int main(int argc, char *argv[]){
	
	char *interface = NULL, errbuf[5000];
	pcap_t *handle;		
	char filtro[] = "ip and (udp or tcp or icmp)";
	

	struct bpf_program fp;	 	//Filter expression
		   bpf_u_int32 mask; 	//Network Mask
		   bpf_u_int32 net;		//IP Address

	if(argv[1] == NULL){
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Nao foi possível encontrar a interface default: %s\n", errbuf);
			return(2);
		}
	} else {
		interface = argv[1];			
	}

	int unsigned buffer = 1;

	if(argv[2] != NULL){
		 buffer = atoi(argv[2]);
	}

	if(argv[3] != NULL){
		 strcpy(filtro, argv[3]);
	}

	//Se retornar erro é -1.
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Não foi possível obter as informações da interface %s: %s\n",interface, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Interface: %s\n", interface);
	printf("Filtro aplicado: %s\n", filtro);
	printf("Pacotes para coletar: %d\n\n", buffer);
	
	printf("Para outra IF \nexecute o programa com a interface como parâmetro. \nExemplo: ./<programa> <interface> \n\n\n");
	

	//*dev é a interface;
	//snaplen é a quantidade de bytes que o pcap poderá ter de buffer; geralmente é definido na pcap.h
	//promisc 1 ou 0 (entrar em modo promíscuo)	;
	//to_ms leitura em MS.
	//ebuf string para armazenar todos os erros obtidos.	
	// pcap_t *pcap_open_live(char *dev, int snaplen, int promisc, int to_ms, char *ebuf)
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Não foi possível capturar dados da interface %s: %s\n", interface, errbuf);
		return(2);
	}

	/* Confirma se é uma interface ethernet */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s não é uma interface ethernet\n", interface);
		return(2);
	}

	//Faz a compilação do filtro.
	if (pcap_compile(handle, &fp, filtro, 0, net) == -1) {
		fprintf(stderr, "Erro na compilação do filtro %s: %s\n",filtro, pcap_geterr(handle));
		return(2);
	}

	//Aplica o filtro compilado.
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Não foi possível aplicar o filtro %s: %s\n",filtro, pcap_geterr(handle));
		return(2);
	}
	
	//while(1){
		pcap_loop(handle, buffer, got_packet, NULL);	
		printf("\n\n");
	//}
	
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\n\n\n\nCaptura finalizada.\n\n\n");

	return(0);
}
