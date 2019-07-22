#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

struct ether_header{
	uint8_t DesMac[6];
	uint8_t SrcMac[6];
	uint16_t Type;
};
struct Ip_Addr
{
	uint8_t byte[4];
};

typedef struct ip_header
{
	u_int8_t  ip_len:4;
	u_int8_t ip_version:4;
	u_int8_t tos; //  
	u_int16_t tolen;  
	u_int16_t identification; 
	u_int16_t flags_fo; 
	u_int8_t ttl; 
	u_int8_t protocal;
	u_int16_t crc; 
	struct Ip_Addr saddr; 
	struct Ip_Addr daddr; 
}ip_header;
struct TCPH {
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t seq;
	uint32_t ack;
	uint8_t TLen;
	uint8_t flags; 
	uint16_t wsize;
	uint16_t checksum;
	uint16_t urg;
};



bool PrintEthernetH(const uint8_t * packet);
bool PrintIpH(const uint8_t * packet);
int PrintTcpH(const uint8_t * packet);
void PrintData(const uint8_t * packet);

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test ens33\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		uint32_t tcplen;
		ip_header*tolen;
		bool cot=true;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		cot = PrintEthernetH(packet);
		if(cot==false){
			continue;
		}else
		{
			packet += 14;
			cot = PrintIpH(packet);
			if(cot==false){
				continue;
			}else
			{
				tolen=(ip_header*)packet;
				packet += ((uint16_t)(tolen->ip_len))*4;
				tcplen=PrintTcpH(packet)>>4;
				if(tolen->tolen-tolen->ip_len*4+tcplen*4>0){
					packet+=tcplen*4;
					PrintData(packet);
				}	
			}
		}
	}

	pcap_close(handle);
	return 0;
}

bool PrintEthernetH(const uint8_t * packet){

	ether_header * eh;
	eh = (ether_header*)packet;
	if(eh->Type=0x0800){
		printf("\n=======Ethernet Header=======\n");
		printf("DMac = %02x:%02x:%02x:%02x:%02x:%02x\n",eh->DesMac[0],eh->DesMac[1],eh->DesMac[2],eh->DesMac[3],eh->DesMac[4],eh->DesMac[5]);
		printf("SMac = %02x:%02x:%02x:%02x:%02x:%02x\n\n",eh->SrcMac[0],eh->SrcMac[1],eh->SrcMac[2],eh->SrcMac[3],eh->SrcMac[4],eh->SrcMac[5]);
		return true;
	}else{
		printf("Isn't it IPv4?");
		return false;
	}
}

bool PrintIpH(const uint8_t * packet){
	ip_header * IH;
	IH = (ip_header*)packet;
	if(IH->protocal==0x06){
		printf("\n=======    Ip Header  =======\n"); 
		printf("protocal : TCP\n");
		printf("Src IP  : %d.%d.%d.%d\n", IH->saddr.byte[0],IH->saddr.byte[1],IH->saddr.byte[2],IH->saddr.byte[3]);
    	printf("Dst IP  : %d.%d.%d.%d\n\n", IH->daddr.byte[0],IH->daddr.byte[1],IH->daddr.byte[2],IH->daddr.byte[3]);
		
		return true;
	}else {
		printf("not tcp\n");
		return false;
		
	}
}

int PrintTcpH(const uint8_t * packet){
	TCPH *TcpH;
    TcpH = (TCPH *)packet;
	printf("\n=======  Tcp Header  =======\n");
	printf("Src Port : %02d\n", ntohs(TcpH->SrcPort));
    printf("Dst Port : %02d\n\n", ntohs(TcpH->DstPort));
	return TcpH->TLen;
}

void PrintData(const uint8_t * packet){
	printf("Data :");
	for(int i=0;i<0xA;i++){
			printf("%02x ",*(packet+i));
		}
	
	puts("");
}