#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

 
typedef struct EthernetHeader{

    unsigned char DesMac[6]; //char은 1byte unsigned char을 쓰는이유는 하나의 bit를 페리티체크용으로 쓰기위함

    unsigned char SrcMac[6];

    uint16_t Type; //unsigned uint16_t -> uint16_t로 변경하기

}Eth;

typedef struct IPHeader{

	unsigned char IHL : 4;

    unsigned char Version : 4;

    unsigned char TOS;

    uint16_t TotalLen;

    uint16_t Identifi;

    unsigned char Flagsx : 1;

    unsigned char FlagsD : 1;

    unsigned char FlagsM : 1;

    unsigned int FO : 13;

    unsigned char TTL;

    unsigned char Protocal;

    uint16_t HeaderCheck;

    struct in_addr SrcAdd;

    struct in_addr DstAdd;

}IPH;

typedef struct TCPHeader{

    uint16_t SrcPort;

    uint16_t DstPort;

    unsigned int SN;

    unsigned int AN;

    unsigned char Offset : 8;

    //unsigned char Reserved : 4;


    unsigned char FlagsC : 1;

    unsigned char FlagsE : 1;

    unsigned char FlagsU : 1;

    unsigned char FlagsA : 1;

    unsigned char FlagsP : 1;

    unsigned char FlagsR : 1;

    unsigned char FlagsS : 1;

    unsigned char FlagsF : 1;

    uint16_t Window;

    uint16_t Check;

    uint16_t UP;

}TCPH;

typedef struct HttpH

{

    uint16_t HTTP[10];

}HttpH;

typedef struct Data_
{
	unsigned char Data[10];
}DATA;



int PtEthH(const u_char* packet);
void PtIpH(const u_char* packet);
void PtTcpH(const u_char* packet);
void PtData(const u_char* packet);

unsigned int size_ip;
unsigned int size_tcp;



void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {

	unsigned int length;
	IPH *len;


	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);  //packet에 PCD가 들어감
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		int eth=PtEthH(packet);
		if(eth){ //TCP면 실행
			packet+=14; // (6+6+2) = 14
			PtIpH(packet);
			len = (IPH *)packet;
			length = htons(len->TotalLen)-(uint16_t)(len->IHL)*4; //TotalLen은 ip헤더랑 tcp랑 http가 들어있는 데이터의 길이도 합친거
			//ip헤더의 길이는 IHL(HLEN), 4bit라서 0~15, 하지만 IPv4의 헤더길이는 20~60 따라서 이 필드값 1은 헤더 길이 4를 의미(*4)
			//printf("total len : 0x%x\n",len->TotalLen);
			packet+=(len->IHL)*4;
			size_ip=(len->IHL)*4;
			
			
			PtTcpH(packet);
		
			
			int payload_len=ntohs(len->TotalLen)-(size_ip+size_tcp);

			if(payload_len!=0){
			packet+=size_tcp;

			PtData(packet);
			}
			else{
				printf("No Data\n");
			}
		}
		else{
			break;
		}


	}

	pcap_close(pcap);
}
int PtEthH(const u_char* packet){
	Eth *eth;
	eth=(Eth *)packet;
	IPH *iph;
	iph=(IPH *)(packet+14);

	if(eth->Type == 8){
		if(iph->Protocal == 6){
	printf("\n==========Ethernet Header==========\n");
	printf("Dst Mac : %x:%x:%x:%x:%x:%x\n",eth->DesMac[0],eth->DesMac[1],eth->DesMac[2],eth->DesMac[3],eth->DesMac[4],eth->DesMac[5]);
	printf("Src Mac : %x:%x:%x:%x:%x:%x\n",eth->SrcMac[0],eth->SrcMac[1],eth->SrcMac[2],eth->SrcMac[3],eth->SrcMac[4],eth->SrcMac[5]);
	//printf("Type : %x\n",eth->Type);
		}
		else{
			return 0; //IPv4 가 아니면 안해
		}
	}
	else{
		return 0; //TCP 아니면 안해
	}
}
void PtIpH(const u_char* packet){
	IPH *iph;
	iph = (IPH *)packet;
	printf("==========IP Header==========\n");
	printf("Src IP : %s\n",inet_ntoa(iph->SrcAdd));//32bit
	printf("Dst IP : %s\n",inet_ntoa(iph->DstAdd));//32bit
}
void PtTcpH(const u_char* packet){
	TCPH *tcph;
	
	tcph=(TCPH *)packet;
	size_tcp=((tcph->Offset)>>4)*4;
	printf("==========TCP Header==========\n");
	printf("Src Port : %d\n",ntohs(tcph->SrcPort));//unsinged short는 2byte
	printf("Dst Port : %d\n",ntohs(tcph->DstPort));
	}

void PtData(const u_char* packet){
	DATA *data;
	data=(DATA *)packet;
	printf("==========Data==========\n");
	for(int i=0;i<10;i++){
		printf("%x ",data->Data[i]);
	}
	printf("\n");
}
