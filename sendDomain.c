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

#define TALKER_ADVERTISE_ATTR_LENGTH 25
#define TALKER_FAILED_ATTR_LENGTH 34
#define LISTENER_DECLARATION_ATTR_LENGTH 8
#define DOMAIN_ATTR_LENGTH 4

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
	unsigned char destaddr[16];
	unsigned char sourceaddr[16];
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

char target_addr[16] = {0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
char src_addr[16] = {0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
char dst_addr[16]={ 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x0, 0x0, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1};
char lladdr[6]={0x12, 0x12, 0x12,0x12, 0x12, 0x12};

void processNA(unsigned char * data);
void forge_udp_ns() {
	char buf[1500];
	char * buf_ptr;
	unsigned int data_len = 0;

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
	memcpy(unh.target_address, target_addr ,16);
	unh.op_type=1;
	unh.op_length=1;
	memcpy(unh.lladdr, lladdr,6);
	
	memcpy(buf_ptr, (char *)&unh, sizeof(unh));

	uh.sourceport = htons(12345);
	uh.destinationport = htons(12345);
	uh.udp_length = htons(40);
	uh.udp_checksum = htons(0);

	buf_ptr -= sizeof(uh);
	data_len += sizeof(uh);
	memcpy(buf_ptr, (char *)&uh, sizeof(uh));

	ih.ver_tc_flow_label=96;
	ih.payload_length=htons(40);
	ih.hop_limit=64;
	ih.nh=17;
	memcpy(ih.sourceaddr, src_addr ,16);
	memcpy(ih.destaddr, dst_addr ,16);

	
	buf_ptr -= sizeof(ih);
	data_len += sizeof(ih);
	memcpy(buf_ptr, (char *)&ih, sizeof(ih));

	eh.etherType = htons(0x86dd);
	memcpy(eh.srcaddr, STATION_ADDR, sizeof(eh.srcaddr));
	memcpy(eh.destaddr, MSRP_ADDR, sizeof(eh.destaddr));

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

	processNA((unsigned char *)buf_ptr);
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
	forge_udp_ns();

	sleep(4000);
	received = recv(msrp_sock, buffer, 1500, 0);
	processMsrp(buffer);

	close(msrp_sock);
	close(udp_sock);
	return 0;
}

void processMsrp(unsigned char *data) {
	unsigned char* ptr;
	unsigned char channel_number;
	unsigned char ipv6_prefix[16];
	unsigned char prefix_length;
	unsigned char default_gw[16];
	unsigned char primary_dns[16];
	unsigned char mac_address[6];
	unsigned char string_prefix[256];

	/*3D location*/
	unsigned char* ptr2;
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


	ptr = data;

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
	
	printf("Default gateway : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], ipv6_prefix[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

	std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], ipv6_prefix[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

	std::string str = "ip -6 route add default via ";
	str = str + default_gw_string;

	std::string dev = " dev ";
	std::string interface_str (interface);
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
	unsigned char lladdr[6];

	unsigned char string_prefix[256];

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

	ptr += 2;

	
	for(int i = 0; i < 6; i++) {
		lladdr[i] = *ptr;
		ptr++;
	}//lladdr
	
	printf("lladdr : %02x:%02x:%02x:%02x:%02x:%02x\n", lladdr[0], lladdr[1], lladdr[2], lladdr[3], lladdr[4], lladdr[5]);

	/*std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], ipv6_prefix[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);

	std::string str = "ip -6 route add default via ";
	str = str + default_gw_string;

	std::string dev = " dev ";
	std::string interface_str (interface);
	str = str + dev;
	str = str + interface_str;
	
	system(str.c_str());

    */
	
    /*
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
    */
}
