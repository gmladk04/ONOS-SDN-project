#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include "sys/types.h"

#include <memory>
#include <stdexcept>
#include <string>

#include <math.h>
#ifdef MRP_CPPUTEST
size_t mrpd_send(SOCKET sockfd, const void* buf, size_t len, int flags);
#else
#define mrpd_send send
#endif

#define BUF_LEN 128

// IPv6 address length (in byte)
#define IPv6_ALEN 16
// IPv6 address string max length
#define IPv6_ADDR_STR_MAX_LEN ((IPv6_ALEN*2)+7)


#define TALKER_ADVERTISE_ATTR_LENGTH 25
#define TALKER_FAILED_ATTR_LENGTH 34
#define LISTENER_DECLARATION_ATTR_LENGTH 8
#define DOMAIN_ATTR_LENGTH 4

#ifndef _SHA1_H 
#define _SHA1_H 

#ifndef uint8 
#define uint8  unsigned char 
#endif 

#ifndef uint32 
#define uint32 unsigned long int 
#endif 

typedef struct 
{ 
    uint32 total[2]; 
    uint32 state[5]; 
    uint8 buffer[64]; 
} 
sha1_context; 

void sha1_starts( sha1_context *ctx ); 
void sha1_update( sha1_context *ctx, uint8 *input, uint32 length ); 
void sha1_finish( sha1_context *ctx, uint8 digest[20] ); 

#endif /* sha1.h */ 

unsigned char MSRP_ADDR[] = { 0x08, 0x00, 0x27, 0x00, 0x00, 0x0E };
unsigned char STATION_ADDR[] = { 0x32, 0xd8, 0xb9, 0xc0, 0x84, 0xfd };

struct eth_header {
	unsigned char destaddr[6];
	unsigned char srcaddr[6];
	unsigned short etherType;
};

struct vector {
	unsigned char* three_events;
	unsigned char* four_events;
	unsigned int allocated;
};

struct vector_attribute {
	unsigned short vh;
	unsigned int firstValue; // ptr
	struct vector vec;
	struct vector_attribute* next;
};

struct message {
	unsigned char attrType;
	unsigned char attributeLength;
	unsigned short attributeListLength;
	struct vector_attribute va;
	unsigned short endMark;

	struct message* next;
};

struct mrpdu {
	unsigned char protocolVersion;
	struct message msg;
	unsigned short endMark;
};

struct ipv6_header {
	unsigned int ver_tc_flow_label;
	unsigned short payload_length;
	unsigned char nh;
	unsigned char hop_limit;
	unsigned char sourceaddr[16];
	unsigned char destaddr[16];
};

struct udp_header {
	unsigned short sourceport;
	unsigned short destinationport;
	unsigned short udp_length;
	unsigned short udp_checksum;
};

struct udp_ns_header {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned int reserved;
	unsigned char target_address[16];
	unsigned char op_type;
	unsigned char op_length;
	unsigned char lladdr[6];	
};

template<typename ... Args>
std::string string_format( const std::string& format, Args ... args )
{
    int size_s = std::snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
    if( size_s <= 0 ){ throw std::runtime_error( "Error during formatting." ); }
    auto size = static_cast<size_t>( size_s );
    std::unique_ptr<char[]> buf( new char[ size ] );
    std::snprintf( buf.get(), size, format.c_str(), args ... );
    return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
}

int msrp_sock;
int udp_sock;

char* interface;
double dist_max=0;

bool abc = false;


char first_dst[IPv6_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
char target_addr[16] = {0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};//
char src_addr[16] = {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x0, 0x0, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1};
char dst_addr[16]={0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
char lladdr[6]={0x12, 0x12, 0x12,0x12, 0x12, 0x12};



unsigned char iid[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78, 0x12, 0x12, 0x12, 0x12,0x12, 0x12}; //iid 


//void processHandoverIntra(unsigned char *data);

void processNA(unsigned char * data);

unsigned short calculateUdpChecksum(struct ipv6_header * ih, unsigned int ih_len, unsigned char * uh, unsigned int uh_len, unsigned char * udp_payload, unsigned int payload_length) {
	unsigned short * ptr;
	unsigned int checksum_result = 0;

	ptr = (unsigned short *)(ih->sourceaddr);
	for(int i = 0; i < 16; i += 2) {
		checksum_result += ntohs(*ptr);
		printf("%04x\n", ntohs(*ptr));
		ptr += 1;
	}

	ptr = (unsigned short *)(ih->destaddr);
	for(int i = 0; i < 16; i += 2) {
		checksum_result += ntohs(*ptr);
		printf("%04x\n", ntohs(*ptr));
		ptr += 1;
	}

	unsigned int upper_layer_length = htonl(uh_len + payload_length);
	ptr = (unsigned short *)(&upper_layer_length);
	for(int i = 0; i < 4; i += 2) {
		checksum_result += ntohs(*ptr);
		printf("%04x\n", ntohs(*ptr));
		ptr += 1;
	}

	unsigned int zero_nh = htonl(17);
	ptr = (unsigned short *)(&zero_nh);
	for(int i = 0; i < 4; i += 2) {
		checksum_result += ntohs(*ptr);
		printf("%04x\n", ntohs(*ptr));
		ptr += 1;
	}

	ptr = (unsigned short *)uh;
	for(int i = 0; i < uh_len; i += 2) {
		checksum_result += ntohs(*ptr);
		printf("%04x\n", ntohs(*ptr));
		ptr += 1;
	}

	if((payload_length % 2) == 1) {
		unsigned char udp_payload_padded[payload_length + 1];
		memcpy(udp_payload_padded, udp_payload, payload_length);
		udp_payload_padded[payload_length] = 0;

		ptr = (unsigned short *)udp_payload_padded;
		for(int i = 0; i < payload_length+1; i += 2) {
			checksum_result += ntohs(*ptr);
			printf("%04x\n", ntohs(*ptr));
			ptr += 1;
		}
	} else {
		ptr = (unsigned short *)udp_payload;
		for(int i = 0; i < payload_length; i += 2) {
			checksum_result += ntohs(*ptr);
			printf("%04x\n", ntohs(*ptr));
			ptr += 1;
		}
	}

	unsigned short carry = ((checksum_result) >> 16);
	unsigned short final_result = (checksum_result & 0xFFFF);

	final_result += carry;
	
	final_result = ~final_result;

	printf("%04x\n", final_result);

	return final_result;
}

void forge_udp_ns( unsigned char *my_ip, unsigned char * dest_ip, unsigned char * dest_mac) {
	char buf[1500];
	char * buf_ptr;
	char buf_na[1500];
	unsigned int data_len = 0;
	unsigned int received=0;

	struct udp_ns_header unh;
	struct udp_header uh;
	struct ipv6_header ih;
	struct eth_header eh;

	buf_ptr = buf + 1500;

	buf_ptr -= sizeof(unh);
	data_len += sizeof(unh);
	
	unh.type=135;
	unh.code =0;
	unh.checksum=htons(0);
	unh.reserved=htons(0);
	memcpy(unh.target_address, my_ip ,16);
	unh.op_type=1;
	unh.op_length=1;
	memcpy(unh.lladdr, lladdr,6);
	
	memcpy(buf_ptr, (char *)&unh, sizeof(unh));

	uh.sourceport = htons(54321);
	uh.destinationport = htons(54321);
	uh.udp_length = htons(40);
	uh.udp_checksum = htons(0);



	ih.ver_tc_flow_label=96;
	ih.payload_length=htons(40);
	ih.hop_limit=64;
	ih.nh=17;
	memset(ih.sourceaddr,0, 16);
	memcpy(ih.destaddr, dest_ip ,16);

	uh.udp_checksum = htons(calculateUdpChecksum(&ih, sizeof(ih), (unsigned char *)&uh, sizeof(uh), (unsigned char *)&unh, sizeof(unh)));

	buf_ptr -= sizeof(uh);
	data_len += sizeof(uh);
	memcpy(buf_ptr, (char *)&uh, sizeof(uh));
	
	buf_ptr -= sizeof(ih);
	data_len += sizeof(ih);
	memcpy(buf_ptr, (char *)&ih, sizeof(ih));

	eh.etherType = htons(0x86dd);
	memcpy(eh.srcaddr, STATION_ADDR, sizeof(eh.srcaddr));
	memcpy(eh.destaddr, dest_mac, sizeof(eh.destaddr));

	buf_ptr -= sizeof(eh);
	data_len += sizeof(eh);
	memcpy(buf_ptr, (char *)&eh, sizeof(eh));

	send(udp_sock, buf_ptr, data_len, 0);

	char addr[7];
	memcpy(addr, STATION_ADDR, 6);
	addr[6] = 0;
	printf("Hi %s\n", addr);
	for(int i = 0; i < 6; i++) {
			printf("%x\n", addr[i]);
	}
	while(true) {
		char * temp;
		received = recv(udp_sock, buf_na, 1500, 0);
		temp = buf_na;
		temp += 14;
		temp += 6;
		printf("%d\n", temp);
		if(*temp == 17) {
			unsigned short dstport;
			unsigned short srcport;

			temp += 34;
			srcport = htons(*((unsigned short *)temp));
			temp += 2;
			dstport = htons(*((unsigned short *)temp));
			printf("%d %d\n", srcport, dstport);
			if(srcport == 54321 && dstport == 54321) {
				break;
			}
		}
	}
	
	processNA((unsigned char *)buf_na);
}

void forge_udp_ns_intra(unsigned char *my_ip, unsigned char * dest_ip, unsigned char * dest_mac) { //code == 1
	char buf[1500];
	char * buf_ptr;
	char buf_na[1500];
	unsigned int data_len = 0;
	unsigned int received=0;	
	struct udp_ns_header unh;
	struct udp_header uh;
	struct ipv6_header ih;
	struct eth_header eh;

	buf_ptr = buf + 1500;

	buf_ptr -= sizeof(unh);
	data_len += sizeof(unh);
	
	unh.type=135;
	unh.code =1; //handover intra
	unh.checksum=htons(0);
	unh.reserved=htons(0);
	memcpy(unh.target_address, my_ip ,16);
	unh.op_type=1;
	unh.op_length=1;
	memcpy(unh.lladdr, lladdr,6);
	
	memcpy(buf_ptr, (char *)&unh, sizeof(unh));

	uh.sourceport = htons(54321);
	uh.destinationport = htons(54321);
	uh.udp_length = htons(40);
	uh.udp_checksum = htons(0);


	
	ih.ver_tc_flow_label=96;
	ih.payload_length=htons(40);
	ih.hop_limit=64;
	ih.nh=17;
	memcpy(ih.sourceaddr, my_ip ,16);
	memcpy(ih.destaddr, dest_ip ,16);

	uh.udp_checksum = htons(calculateUdpChecksum(&ih, sizeof(ih), (unsigned char *)&uh, sizeof(uh), (unsigned char *)&unh, sizeof(unh)));

	buf_ptr -= sizeof(uh);
	data_len += sizeof(uh);
	memcpy(buf_ptr, (char *)&uh, sizeof(uh));
	
	buf_ptr -= sizeof(ih);
	data_len += sizeof(ih);
	memcpy(buf_ptr, (char *)&ih, sizeof(ih));

	eh.etherType = htons(0x86dd);
	memcpy(eh.srcaddr, STATION_ADDR, sizeof(eh.srcaddr));
	memcpy(eh.destaddr, dest_mac, sizeof(eh.destaddr));

	buf_ptr -= sizeof(eh);
	data_len += sizeof(eh);
	memcpy(buf_ptr, (char *)&eh, sizeof(eh));

	send(udp_sock, buf_ptr, data_len, 0);

	char addr[7];
	memcpy(addr, STATION_ADDR, 6);
	addr[6] = 0;
	printf("Hi %s\n", addr);
	for(int i = 0; i < 6; i++) {
			printf("%x\n", addr[i]);
	}
	
	while(true) {
		char * temp;
		received = recv(udp_sock, buf_na, 1500, 0);
		temp = buf_na;
		temp += 14;
		temp += 6;
		if(*temp == 17) {
			unsigned short dstport;
			unsigned short srcport;

			temp += 34;
			srcport = htons(*((unsigned short *)temp));
			temp += 2;
			dstport = htons(*((unsigned short *)temp));
			printf("%d %d\n", srcport, dstport);
			if(srcport == 54321 && dstport == 54321) {
				break;
			}
		}
	}
	
	processNA((unsigned char *)buf_na);
}

void forge_udp_ns_inter(unsigned char *my_ip, unsigned char * dest_ip, unsigned char * dest_mac) { //code == 2
	char buf[1500];
	char * buf_ptr;
	char buf_na[1500];
	unsigned int data_len = 0;
	unsigned int received=0;
	struct udp_ns_header unh;
	struct udp_header uh;
	struct ipv6_header ih;
	struct eth_header eh;

	buf_ptr = buf + 1500;

	buf_ptr -= sizeof(unh);
	data_len += sizeof(unh);
	
	unh.type=135;
	unh.code =2; //handover inter
	unh.checksum=htons(0);
	unh.reserved=htons(0);
	memcpy(unh.target_address, my_ip ,16);
	unh.op_type=1;
	unh.op_length=1;
	memcpy(unh.lladdr, lladdr,6);
	
	memcpy(buf_ptr, (char *)&unh, sizeof(unh));

	uh.sourceport = htons(54321);
	uh.destinationport = htons(54321);
	uh.udp_length = htons(40);
	uh.udp_checksum = htons(0);


	ih.ver_tc_flow_label=96;
	ih.payload_length=htons(40);
	ih.hop_limit=64;
	ih.nh=17;
	memset(ih.sourceaddr, 0 ,16);
	memcpy(ih.destaddr, dest_ip,16);

	uh.udp_checksum = htons(calculateUdpChecksum(&ih, sizeof(ih), (unsigned char *)&uh, sizeof(uh), (unsigned char *)&unh, sizeof(unh)));

	buf_ptr -= sizeof(uh);
	data_len += sizeof(uh);
	memcpy(buf_ptr, (char *)&uh, sizeof(uh));

	buf_ptr -= sizeof(ih);
	data_len += sizeof(ih);
	memcpy(buf_ptr, (char *)&ih, sizeof(ih));

	eh.etherType = htons(0x86dd);
	memcpy(eh.srcaddr, STATION_ADDR, sizeof(eh.srcaddr));
	memcpy(eh.destaddr, dest_mac, sizeof(eh.destaddr));

	buf_ptr -= sizeof(eh);
	data_len += sizeof(eh);
	memcpy(buf_ptr, (char *)&eh, sizeof(eh));

	send(udp_sock, buf_ptr, data_len, 0);

	char addr[7];
	memcpy(addr, STATION_ADDR, 6);
	addr[6] = 0;
	//printf("Hi %s\n", addr);
	for(int i = 0; i < 6; i++) {
			printf("%x\n", addr[i]);
	}

	while(true) {
		char * temp;
		received = recv(udp_sock, buf_na, 1500, 0);
		temp = buf_na;
		temp += 14;
		temp += 6;
		if(*temp == 17) {
			unsigned short dstport;
			unsigned short srcport;

			temp += 34;
			srcport = htons(*((unsigned short *)temp));
			temp += 2;
			dstport = htons(*((unsigned short *)temp));
			printf("%d %d\n", srcport, dstport);
			if(srcport == 54321 && dstport == 54321) {
				break;
			}
		}
	}
	
	processNA((unsigned char *)buf_na);
}

int mrpd_init_protocol_socket(u_int16_t etype, int* sock, unsigned char* multicast_addr);
void sendMsrp(struct message* msg);
void processMsrp(unsigned char* data);

unsigned char* parseEtherAddress(unsigned char* data) {
	unsigned char* ethAddr = (unsigned char*)malloc(6);
	int i = 0;
	int filled = 0;
	int halfFilled = 0;
	for (i = 0; 1; i++) {
		if (filled == 6)
			break;
		if (data[i] >= '0' && data[i] <= '9') {

			if (halfFilled) {
				ethAddr[filled++] += (data[i] - '0');
				halfFilled = 0;
			}
			else {
				ethAddr[filled] = ((data[i] - '0') << 4);
				halfFilled = 1;
			}
			continue;
		}
		if (data[i] >= 'a' && data[i] <= 'f') {
			if (halfFilled) {
				ethAddr[filled++] += ((data[i] - 'a') + 10);
				halfFilled = 0;
			}
			else {
				ethAddr[filled] = (((data[i] - 'a') + 10) << 4);
				halfFilled = 1;
			}
			continue;
		}
		if (data[i] >= 'A' && data[i] <= 'F') {
			if (halfFilled) {
				ethAddr[filled++] += ((data[i] - 'A') + 10);
				halfFilled = 0;
			}
			else {
				ethAddr[filled] = (((data[i] - 'A') + 10) << 4);
				halfFilled = 1;
			}
			continue;
		}
	}
	return ethAddr;
}
struct stream_id {
	unsigned char ethAddr[6];
	unsigned short unique_id;
};

struct dataframe_params {
	unsigned char dstAddr[6];
	unsigned short vlan_id;
};

struct tspec {
	unsigned short max_frame_size;
	unsigned short max_interval;
};

struct failure_info {
	unsigned char system_id[8];
	unsigned char f_code;
};

struct talkerAdvertiseFirstValue {
	struct stream_id sid;
	struct dataframe_params dfp;
	struct tspec ts;
	unsigned char par;
	unsigned int accumulated_latency;
};

struct talkerFailedFirstValue {
	struct stream_id sid;
	struct dataframe_params dfp;
	struct tspec ts;
	unsigned char par;
	unsigned int accumulated_latency;
	struct failure_info f_info;
};

struct ListenerDeclarationFirstValue {
	struct stream_id sid;
};

struct DomainFirstValue {
	unsigned char classId;
	unsigned char priority;
	unsigned short vlan_id;
};



int main(int argc, char* argv[]) {
	struct message* msg;
	struct mrpdu* mrp_frame;
	unsigned char vectors[] = { 2 };
	unsigned char buffer[1500];
	unsigned int received=0;
	unsigned char classId;
	unsigned char priority;
	unsigned short vlan_id;
	//unsigned char test[] = {0x03,0x00,0x80,0x07,0x7c,0x03,0x00,0x79,0x3f,0x11,0x03,0x11,0x01,0x64,0x06,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x05,0x04,0x4a,0x4d,0x43,0x52,0x01,0xef,0xff,0xff,0xfe,0x08,0x01,0x0b,0xac,0x9e,0x0c,0x01,0x02,0x0c,0x04,0x06,0xa4,0x00,0x00,0x15,0x01,0x02,0x07,0x08,0x12,0x34,0x0d,0xb8,0xf0,0x0d,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0xff,0xfe,0x00,0x00,0x08,0x10,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x08,0x00,0x00,0x01,0x00,0x01,0x01,0x0e,0x06,0x00,0x00,0x00,0x00,0x00,0x08};

	interface = strdup(argv[1]);

	mrpd_init_protocol_socket(0x88DC, &msrp_sock, MSRP_ADDR);
	mrpd_init_protocol_socket(0x86DD, &udp_sock, MSRP_ADDR);
	
	received = recv(msrp_sock, buffer, 1500, 0);
	
	processMsrp(buffer);

	pid_t pid;
	if((pid=fork())<0){
		//
	}
	if(pid ==0 ){

	}else{
		while(1) {
		received = recv(msrp_sock, buffer, 1500, 0);
		processMsrp(buffer);	
	}
	}

	

	close(msrp_sock);
	close(udp_sock);
	
	return 0;
}
unsigned char default_gw[16];
unsigned char primary_dns[16];

unsigned char string_prefix[256];

unsigned char * current_prefix = NULL;
unsigned char current_ip[16];
unsigned char * current_gw_mac = NULL;

void
MakeHashedIid(unsigned char * prefix, unsigned char * net_iface, unsigned char netif_len, unsigned char * net_id, unsigned char netid_len, unsigned char dad_counter, unsigned char * secret_key, unsigned char * result) {
	sha1_context ctx;
	unsigned char sha1sum[20];

	unsigned char * buffer;
	unsigned char * ptr;

	unsigned int total_len = 8 + netif_len + netid_len + 1 + 16;
	buffer = (uint8_t *)malloc(total_len);

	ptr = buffer;

	memcpy(ptr, prefix, 8);
	ptr = ptr + 8;

	memcpy(ptr, net_iface, netif_len);
	ptr = ptr + netif_len;

	if(net_id == NULL) {
		memset(ptr, 0, netid_len);
		ptr = ptr + netid_len;
	} else {
		memcpy(ptr, net_id, netid_len);
		ptr = ptr + netid_len;
	}

	*ptr = dad_counter;
	ptr += 1;

	memset(ptr, 0, 16);

	sha1_starts(&ctx);
	sha1_update(&ctx, buffer, total_len);
	sha1_finish(&ctx, sha1sum);

	memcpy(result, sha1sum + 12, 8);
}

void processMsrp(unsigned char *data) {
	unsigned char* ptr;
	unsigned char channel_number;
	unsigned char ipv6_prefix[16];
	unsigned char prefix_length;
	unsigned char mac_address[6];

	/*3D location*/
	/*unsigned char* ptr2;
	double dist=0;
	double x;
	double y;
	double z;
	unsigned char *ptr3;
	
	ptr2=data;
	ptr2+=30;
	ptr3 = ptr2;

	x=*((double *)ptr3);
	ptr3 += 8;

	y=*((double *)ptr3);
	ptr3 += 8;

	z=*((double *)ptr3);

	printf("3D location: %lf  %lf  %lf\n\n", x, y, z);

*/
	ptr = data;

	ptr += 6;

	//printf("%2x:%2x:%2x:%2x:%2x:%2x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	if(current_gw_mac == NULL) {
		current_gw_mac = (unsigned char *)malloc(6);
		memcpy(current_gw_mac, ptr, 6);
	} else if (!memcmp(current_gw_mac, ptr, 6)) {
		return;
	} else {
		memcpy(current_gw_mac, ptr, 6);
	}

	ptr += 8;

	ptr += 53;
	
	
	// Channel Info start
	ptr++;

	channel_number = *ptr;
	
	ptr++;
	printf("Channel Number : %d\n", channel_number);

	ptr += 16;
	
	for(int i = 0; i < 16; i++) {
		ipv6_prefix[i] = *ptr;
		ptr++;
	}

	printf("IPv6 Prefix : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6_prefix[0], ipv6_prefix[1], ipv6_prefix[2], ipv6_prefix[3], ipv6_prefix[4], ipv6_prefix[5], ipv6_prefix[6], ipv6_prefix[7], ipv6_prefix[8], ipv6_prefix[9], ipv6_prefix[10], ipv6_prefix[11], ipv6_prefix[12], ipv6_prefix[13], ipv6_prefix[14], ipv6_prefix[15]);

	prefix_length = *ptr;
	ptr++;

	printf("Prefix Length : %d\n", prefix_length);

	
	for(int i = 0; i < 16; i++) {
		default_gw[i] = *ptr;
		ptr++;
	}//default gateway
	
	printf("Default gateway : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], default_gw[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

	std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], default_gw[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

	std::string str = "ip -6 route add default via ";
	str = str + default_gw_string;

	std::string dev = " dev ";
	std::string interface_str (interface);
	str = str + dev;
	str = str + interface_str;
	
	system(str.c_str());

	str = "ip -6 route replace default via ";
	str = str + default_gw_string;

	str = str + dev;
	str = str + interface_str;
	
	system(str.c_str());	

	
	for(int i = 0; i < 16; i++) {
		primary_dns[i] = *ptr;
		ptr++;
	}//dns
	printf("primary_dns : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", primary_dns[0], primary_dns[1], primary_dns[2], primary_dns[3], primary_dns[4], primary_dns[5], primary_dns[6], primary_dns[7], primary_dns[8], primary_dns[9], primary_dns[10], primary_dns[11], primary_dns[12], primary_dns[13], primary_dns[14], primary_dns[15]);

	ptr += 3;
	
	
	for(int i = 0; i < 6; i++) {
		mac_address[i] = *ptr;
		ptr++;
	}//mac_address
	printf("mac_address : %02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);

	std::string default_gw_mac_string = string_format("%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
	// ip -6 neigh add <IPv6 address> lladdr <link-layer address> dev <device>
	std::string str_neigh = "ip -6 neigh add ";
	str_neigh = str_neigh + default_gw_string;

	std::string str_lladdr = " lladdr ";
	str_neigh = str_neigh + str_lladdr;
	str_neigh = str_neigh + default_gw_mac_string;
	str_neigh = str_neigh + dev;
	str_neigh = str_neigh + interface_str;

	system(str_neigh.c_str());

	if(current_prefix == NULL) { // case 1 
		unsigned char vehicle_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22};
		current_prefix = (unsigned char *)malloc(16);
		memcpy(current_prefix, ipv6_prefix, 16);
		unsigned char generated_address[16];
		MakeHashedIid(ipv6_prefix, vehicle_mac, 6, NULL, 8, 0, NULL, iid);
		memcpy(generated_address + 8, iid, 8);
		memcpy(generated_address, ipv6_prefix, 8);

		forge_udp_ns(generated_address, default_gw, mac_address);
	} else if (!memcmp(current_prefix, ipv6_prefix,16)) {
		forge_udp_ns_intra(current_ip, default_gw, mac_address);
	} else {
		unsigned char vehicle_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x22};
		memcpy(current_prefix, ipv6_prefix, 16);
		unsigned char generated_address[16];
		MakeHashedIid(ipv6_prefix, vehicle_mac, 6, NULL, 8, 0, NULL, iid);
		memcpy(generated_address + 8, iid, 8);
		memcpy(generated_address, ipv6_prefix, 8);

		forge_udp_ns_inter(current_ip,default_gw, mac_address);
		forge_udp_ns(generated_address, default_gw, mac_address);
	}
}


int mrpd_init_protocol_socket(u_int16_t etype, int* sock,
	unsigned char* multicast_addr)
{
	struct sockaddr_ll addr;
	struct ifreq if_request;
	int lsock;
	int rc;
	struct packet_mreq multicast_req;

	if (NULL == sock)
		return -1;
	if (NULL == multicast_addr)
		return -1;

	memset(&multicast_req, 0, sizeof(multicast_req));
	*sock = -1;

	lsock = socket(PF_PACKET, SOCK_RAW, htons(etype));

	if (lsock < 0) {
		printf("Socket Creation Error\n");
		return -1;
	}

	memset(&if_request, 0, sizeof(if_request));

	strncpy(if_request.ifr_name, interface, sizeof(if_request.ifr_name) - 1);


	rc = ioctl(lsock, SIOCGIFHWADDR, &if_request);
	if (rc < 0) {
		printf("IOCTL Error\n");
		close(lsock);
		return -1;
	}

	memcpy(STATION_ADDR, if_request.ifr_hwaddr.sa_data,
		sizeof(STATION_ADDR));

	memset(&if_request, 0, sizeof(if_request));

	strncpy(if_request.ifr_name, interface, sizeof(if_request.ifr_name) - 1);

	rc = ioctl(lsock, SIOCGIFINDEX, &if_request);
	if (rc < 0) {
		printf("IOCTL2 Error\n");
		close(lsock);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_request.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(etype);

	rc = bind(lsock, (struct sockaddr*)&addr, sizeof(addr));
	if (0 != rc) {
#if LOG_ERRORS
		fprintf(stderr, "%s - Error on bind %s", __FUNCTION__, strerror(errno));
#endif
		close(lsock);
		return -1;
	}

	rc = setsockopt(lsock, SOL_SOCKET, SO_BINDTODEVICE, interface,
		strlen(interface));
	if (0 != rc) {
		printf("Bind option error\n");
		close(lsock);
		return -1;
	}

	*sock = lsock;

	return 0;
}

void processNA(unsigned char* data) {
	unsigned char* ptr;
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned int reserved;
	unsigned char target_address[16];
	unsigned char op_type;
	unsigned char op_length;
	unsigned char mac_address[6];


	ptr = data;

	ptr += 61;
	
	// Channel Info start
	ptr++;

	type = *ptr;
	ptr++;

	printf("Type : %d\n", type);

	code = *ptr;
    ptr++;
    printf("code : %d\n", code);

    ptr += 6;//checksum & reserved


	for(int i = 0; i < 16; i++) {
		target_address[i] = *ptr;
		ptr++;
	}
	

	printf("Target Address : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", target_address[0], target_address[1], target_address[2], target_address[3], target_address[4], target_address[5], target_address[6], target_address[7], target_address[8], target_address[9], target_address[10], target_address[11], target_address[12], target_address[13], target_address[14], target_address[15]);

	ptr += 2; //type length

	std::string new_ip = string_format("ifconfig sta1-wlan0 inet add %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", target_address[0], target_address[1], target_address[2], target_address[3], target_address[4], target_address[5], target_address[6], target_address[7], target_address[8], target_address[9], target_address[10], target_address[11], target_address[12], target_address[13], target_address[14], target_address[15]);

	system(new_ip.c_str());

	for(int i = 0; i < 6; i++) {
		mac_address[i] = *ptr;
		ptr++;
	}//lladdr
	
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);

	if(code == 0) {
		memcpy(current_ip, target_address, 16);

		
	}

	/* Handover intra or inter */
	if(code == 1 ){

	
	
		std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], default_gw[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

		std::string str = "ip -6 route replace default via ";
		str = str + default_gw_string;

		std::string dev = " dev ";
		std::string interface_str (interface);
		str = str + dev;
		str = str + interface_str;
	
		system(str.c_str());	


		std::string default_gw_mac_string = string_format("%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
	// ip -6 neigh replace <IPv6 address> lladdr <link-layer address> dev <device>
		std::string str_neigh = "ip -6 neigh add ";
		str_neigh = str_neigh + default_gw_string;

		std::string str_lladdr = " lladdr ";
		str_neigh = str_neigh + str_lladdr;
		str_neigh = str_neigh + default_gw_mac_string;
		str_neigh = str_neigh + dev;
		str_neigh = str_neigh + interface_str;

		system(str_neigh.c_str());

	}
	
	if(code ==2 ){
	
		
		std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], default_gw[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

		std::string str = "ip -6 route replace default via ";
		str = str + default_gw_string;

		std::string dev = " dev ";
		std::string interface_str (interface);
		str = str + dev;
		str = str + interface_str;
	
		system(str.c_str());	

		
		printf("mac_address : %02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);

		std::string default_gw_mac_string = string_format("%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
	// ip -6 neigh replace <IPv6 address> lladdr <link-layer address> dev <device>
		std::string str_neigh = "ip -6 neigh add ";
		str_neigh = str_neigh + default_gw_string;

		std::string str_lladdr = " lladdr ";
		str_neigh = str_neigh + str_lladdr;
		str_neigh = str_neigh + default_gw_mac_string;
		str_neigh = str_neigh + dev;
		str_neigh = str_neigh + interface_str;

		system(str_neigh.c_str());

	}


	
}

/* 
 *  FIPS-180-1 compliant SHA-1 implementation 
 * 
 *  Copyright (C) 2001-2003  Christophe Devine 
 * 
 *  This program is free software; you can redistribute it and/or modify 
 *  it under the terms of the GNU General Public License as published by 
 *  the Free Software Foundation; either version 2 of the License, or 
 *  (at your option) any later version. 
 * 
 *  This program is distributed in the hope that it will be useful, 
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 *  GNU General Public License for more details. 
 * 
 *  You should have received a copy of the GNU General Public License 
 *  along with this program; if not, write to the Free Software 
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */ 

#include <string.h> 

#include "sha1.h" 

#define GET_UINT32(n,b,i)                       \ 
{                                               \ 
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \ 
        | ( (uint32) (b)[(i) + 1] << 16 )       \ 
        | ( (uint32) (b)[(i) + 2] <<  8 )       \ 
        | ( (uint32) (b)[(i) + 3]       );      \ 
} 

#define PUT_UINT32(n,b,i)                       \ 
{                                               \ 
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \ 
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \ 
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \ 
    (b)[(i) + 3] = (uint8) ( (n)       );       \ 
} 

void sha1_starts( sha1_context *ctx ) 
{ 
    ctx->total[0] = 0; 
    ctx->total[1] = 0; 

    ctx->state[0] = 0x67452301; 
    ctx->state[1] = 0xEFCDAB89; 
    ctx->state[2] = 0x98BADCFE; 
     ctx->state[3] = 0x10325476; 
    ctx->state[4] = 0xC3D2E1F0; 
} 

void sha1_process( sha1_context *ctx, uint8 data[64] ) 
{ 
    uint32 temp, W[16], A, B, C, D, E; 

    GET_UINT32( W[0],  data,  0 ); 
    GET_UINT32( W[1],  data,  4 ); 
    GET_UINT32( W[2],  data,  8 ); 
    GET_UINT32( W[3],  data, 12 ); 
    GET_UINT32( W[4],  data, 16 ); 
    GET_UINT32( W[5],  data, 20 ); 
    GET_UINT32( W[6],  data, 24 ); 
    GET_UINT32( W[7],  data, 28 ); 
    GET_UINT32( W[8],  data, 32 ); 
    GET_UINT32( W[9],  data, 36 ); 
    GET_UINT32( W[10], data, 40 ); 
    GET_UINT32( W[11], data, 44 ); 
    GET_UINT32( W[12], data, 48 ); 
    GET_UINT32( W[13], data, 52 ); 
    GET_UINT32( W[14], data, 56 ); 
    GET_UINT32( W[15], data, 60 ); 

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n))) 

#define R(t)                                            \ 
(                                                       \ 
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \ 
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \ 
    ( W[t & 0x0F] = S(temp,1) )                         \ 
) 

#define P(a,b,c,d,e,x)                                  \ 
{                                                       \ 
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \ 
} 

    A = ctx->state[0]; 
    B = ctx->state[1]; 
    C = ctx->state[2]; 
    D = ctx->state[3]; 
    E = ctx->state[4]; 

#define F(x,y,z) (z ^ (x & (y ^ z))) 
#define K 0x5A827999 

    P( A, B, C, D, E, W[0]  ); 
    P( E, A, B, C, D, W[1]  ); 
    P( D, E, A, B, C, W[2]  ); 
    P( C, D, E, A, B, W[3]  ); 
    P( B, C, D, E, A, W[4]  ); 
    P( A, B, C, D, E, W[5]  ); 
    P( E, A, B, C, D, W[6]  ); 
    P( D, E, A, B, C, W[7]  ); 
    P( C, D, E, A, B, W[8]  ); 
    P( B, C, D, E, A, W[9]  ); 
    P( A, B, C, D, E, W[10] ); 
    P( E, A, B, C, D, W[11] ); 
    P( D, E, A, B, C, W[12] ); 
    P( C, D, E, A, B, W[13] ); 
    P( B, C, D, E, A, W[14] ); 
    P( A, B, C, D, E, W[15] ); 
    P( E, A, B, C, D, R(16) ); 
    P( D, E, A, B, C, R(17) ); 
    P( C, D, E, A, B, R(18) ); 
    P( B, C, D, E, A, R(19) ); 

#undef K 
#undef F 

#define F(x,y,z) (x ^ y ^ z) 
#define K 0x6ED9EBA1 

    P( A, B, C, D, E, R(20) ); 
    P( E, A, B, C, D, R(21) ); 
    P( D, E, A, B, C, R(22) ); 
    P( C, D, E, A, B, R(23) ); 
    P( B, C, D, E, A, R(24) ); 
    P( A, B, C, D, E, R(25) ); 
    P( E, A, B, C, D, R(26) ); 
    P( D, E, A, B, C, R(27) ); 
    P( C, D, E, A, B, R(28) ); 
    P( B, C, D, E, A, R(29) ); 
    P( A, B, C, D, E, R(30) ); 
    P( E, A, B, C, D, R(31) ); 
    P( D, E, A, B, C, R(32) ); 
    P( C, D, E, A, B, R(33) ); 
    P( B, C, D, E, A, R(34) ); 
    P( A, B, C, D, E, R(35) ); 
    P( E, A, B, C, D, R(36) ); 
    P( D, E, A, B, C, R(37) ); 
    P( C, D, E, A, B, R(38) ); 
    P( B, C, D, E, A, R(39) ); 

#undef K 
#undef F 

#define F(x,y,z) ((x & y) | (z & (x | y))) 
#define K 0x8F1BBCDC 

    P( A, B, C, D, E, R(40) ); 
    P( E, A, B, C, D, R(41) ); 
    P( D, E, A, B, C, R(42) ); 
    P( C, D, E, A, B, R(43) ); 
    P( B, C, D, E, A, R(44) ); 
    P( A, B, C, D, E, R(45) ); 
    P( E, A, B, C, D, R(46) ); 
    P( D, E, A, B, C, R(47) ); 
    P( C, D, E, A, B, R(48) ); 
    P( B, C, D, E, A, R(49) ); 
    P( A, B, C, D, E, R(50) ); 
    P( E, A, B, C, D, R(51) ); 
    P( D, E, A, B, C, R(52) ); 
    P( C, D, E, A, B, R(53) ); 
    P( B, C, D, E, A, R(54) ); 
    P( A, B, C, D, E, R(55) ); 
    P( E, A, B, C, D, R(56) ); 
    P( D, E, A, B, C, R(57) ); 
    P( C, D, E, A, B, R(58) ); 
    P( B, C, D, E, A, R(59) ); 

#undef K 
#undef F 

#define F(x,y,z) (x ^ y ^ z) 
#define K 0xCA62C1D6 

    P( A, B, C, D, E, R(60) ); 
    P( E, A, B, C, D, R(61) ); 
    P( D, E, A, B, C, R(62) ); 
    P( C, D, E, A, B, R(63) ); 
    P( B, C, D, E, A, R(64) ); 
    P( A, B, C, D, E, R(65) ); 
    P( E, A, B, C, D, R(66) ); 
    P( D, E, A, B, C, R(67) ); 
    P( C, D, E, A, B, R(68) ); 
    P( B, C, D, E, A, R(69) ); 
    P( A, B, C, D, E, R(70) ); 
    P( E, A, B, C, D, R(71) ); 
    P( D, E, A, B, C, R(72) ); 
    P( C, D, E, A, B, R(73) ); 
    P( B, C, D, E, A, R(74) ); 
    P( A, B, C, D, E, R(75) ); 
    P( E, A, B, C, D, R(76) ); 
    P( D, E, A, B, C, R(77) ); 
    P( C, D, E, A, B, R(78) ); 
    P( B, C, D, E, A, R(79) ); 

#undef K 
#undef F 

    ctx->state[0] += A; 
    ctx->state[1] += B; 
    ctx->state[2] += C; 
    ctx->state[3] += D; 
    ctx->state[4] += E; 
} 

void sha1_update( sha1_context *ctx, uint8 *input, uint32 length ) 
{ 
    uint32 left, fill; 

    if( ! length ) return; 

    left = ctx->total[0] & 0x3F; 
    fill = 64 - left; 

    ctx->total[0] += length; 
    ctx->total[0] &= 0xFFFFFFFF; 

    if( ctx->total[0] < length ) 
        ctx->total[1]++; 

    if( left && length >= fill ) 
    { 
        memcpy( (void *) (ctx->buffer + left), 
                (void *) input, fill ); 
        sha1_process( ctx, ctx->buffer ); 
        length -= fill; 
        input  += fill; 
        left = 0; 
    } 

    while( length >= 64 ) 
    { 
        sha1_process( ctx, input ); 
        length -= 64; 
        input  += 64; 
    } 

    if( length ) 
    { 
        memcpy( (void *) (ctx->buffer + left), 
                (void *) input, length ); 
    } 
} 

static uint8 sha1_padding[64] = 
{ 
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 
}; 

void sha1_finish( sha1_context *ctx, uint8 digest[20] ) 
{ 
    uint32 last, padn; 
    uint32 high, low; 
    uint8 msglen[8]; 

    high = ( ctx->total[0] >> 29 ) 
         | ( ctx->total[1] <<  3 ); 
    low  = ( ctx->total[0] <<  3 ); 

    PUT_UINT32( high, msglen, 0 ); 
    PUT_UINT32( low,  msglen, 4 ); 

    last = ctx->total[0] & 0x3F; 
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last ); 

    sha1_update( ctx, sha1_padding, padn ); 
    sha1_update( ctx, msglen, 8 ); 

    PUT_UINT32( ctx->state[0], digest,  0 ); 
    PUT_UINT32( ctx->state[1], digest,  4 ); 
    PUT_UINT32( ctx->state[2], digest,  8 ); 
    PUT_UINT32( ctx->state[3], digest, 12 ); 
    PUT_UINT32( ctx->state[4], digest, 16 ); 
}
