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

unsigned char MSRP_ADDR[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
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

int msrp_sock;
char* interface;

int mrpd_init_protocol_socket(u_int16_t etype, int* sock, unsigned char* multicast_addr);
void sendMsrp(struct message* msg);
struct mrpdu* processMsrp(unsigned char* data);

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

unsigned char* serialize(struct vector_attribute* va, int type, unsigned int* serialized_bytes) {
	unsigned int firstLen;
	unsigned char* origin_ptr;
	unsigned char* buf = NULL;
	unsigned int numofval;

	if (type == 1) { // Talker Advertise
		struct vector_attribute* va_ptr;
		struct talkerAdvertiseFirstValue* tafv;
		unsigned int vector_bytes;
		int i;
		int three;
		unsigned char vector_encoded;

		firstLen = TALKER_ADVERTISE_ATTR_LENGTH;
		numofval = va->vh & 0x1FFF;

		if (va->vec.allocated < numofval) {
			free(buf);
			printf("Serialization Error - Event Number Not sufficient\n");
			return NULL;
		}

		vector_bytes = (unsigned int)((numofval + 2) / 3);
		*serialized_bytes = firstLen + vector_bytes + 2;
		buf = (unsigned char*)malloc(firstLen + vector_bytes + 2);
		origin_ptr = buf;

		*((unsigned short*)buf) = htons(va->vh);
		buf += 2;
		tafv = (struct talkerAdvertiseFirstValue*)va->firstValue;
		memcpy(buf, tafv->sid.ethAddr, 6);
		buf += 6;

		*((unsigned short*)buf) = htons(tafv->sid.unique_id);
		buf += 2;

		memcpy(buf, tafv->dfp.dstAddr, 6);
		buf += 6;

		*((unsigned short*)buf) = htons(tafv->dfp.vlan_id);
		buf += 2;

		*((unsigned short*)buf) = htons(tafv->ts.max_frame_size);
		buf += 2;

		*((unsigned short*)buf) = htons(tafv->ts.max_interval);
		buf += 2;

		*buf = tafv->par;
		buf += 1;

		*((unsigned int*)buf) = htonl(tafv->accumulated_latency);
		buf += 4;

		for (vector_encoded = 0, three = 0, i = 0; i < numofval; i++) {
			if (three == 0) {
				vector_encoded = 0;
				vector_encoded += va->vec.three_events[i] * 36;
			}
			if (three == 1) {
				vector_encoded += va->vec.three_events[i] * 6;
			}
			if (three == 2) {
				vector_encoded += va->vec.three_events[i];
				*buf = vector_encoded;
				buf += 1;

				three = 0;
				continue;
			}
			three++;
		}
		if (three != 0) {
			*buf = vector_encoded;
			buf += 1;
		}
	}
	if (type == 2) { // Talker Failed
		struct vector_attribute* va_ptr;
		struct talkerFailedFirstValue* tffv;
		unsigned int vector_bytes;
		int i;
		int three;
		unsigned char vector_encoded;

		firstLen = TALKER_FAILED_ATTR_LENGTH;
		numofval = va->vh & 0x1FFF;

		if (va->vec.allocated < numofval) {
			free(buf);
			printf("Serialization Error - Event Number Not sufficient\n");
			return NULL;
		}

		vector_bytes = (unsigned int)((numofval + 2) / 3);
		*serialized_bytes = firstLen + vector_bytes + 2;
		buf = (unsigned char*)malloc(firstLen + vector_bytes + 2);
		origin_ptr = buf;

		*((unsigned short*)buf) = htons(va->vh);
		buf += 2;

		tffv = (struct talkerFailedFirstValue*)va->firstValue;
		memcpy(buf, tffv->sid.ethAddr, 6);
		buf += 6;

		*((unsigned short*)buf) = htons(tffv->sid.unique_id);
		buf += 2;

		memcpy(buf, tffv->dfp.dstAddr, 6);
		buf += 6;

		*((unsigned short*)buf) = htons(tffv->dfp.vlan_id);
		buf += 2;

		*((unsigned short*)buf) = htons(tffv->ts.max_frame_size);
		buf += 2;

		*((unsigned short*)buf) = htons(tffv->ts.max_interval);
		buf += 2;

		*buf = tffv->par;
		buf += 1;

		*((unsigned int*)buf) = htonl(tffv->accumulated_latency);
		buf += 4;

		memcpy(buf, tffv->f_info.system_id, 8);
		buf += 8;

		*buf = tffv->f_info.f_code;
		buf += 1;

		for (vector_encoded = 0, three = 0, i = 0; i < numofval; i++) {
			if (three == 0) {
				vector_encoded = 0;
				vector_encoded += va->vec.three_events[i] * 36;
			}
			if (three == 1) {
				vector_encoded += va->vec.three_events[i] * 6;
			}
			if (three == 2) {
				vector_encoded += va->vec.three_events[i];
				*buf = vector_encoded;
				buf += 1;

				three = 0;
				continue;
			}
			three++;
		}
		if (three != 0) {
			*buf = vector_encoded;
			buf += 1;
		}
	}
	if (type == 3) { // Listener Declaration
		struct vector_attribute* va_ptr;
		struct ListenerDeclarationFirstValue* ldfv;
		unsigned int vector_bytes;

		unsigned char vector_encoded;
		unsigned int three;
		unsigned int four;
		int i;

		firstLen = LISTENER_DECLARATION_ATTR_LENGTH;
		numofval = va->vh & 0x1FFF;

		if (va->vec.allocated < numofval) {
			free(buf);
			printf("Serialization Error - Event Number Not sufficient\n");
			return NULL;
		}

		vector_bytes = (unsigned int)(((numofval + 2) / 3) + ((numofval + 3) / 4));
		*serialized_bytes = firstLen + vector_bytes + 2;
		buf = (unsigned char*)malloc(firstLen + vector_bytes + 2);
		origin_ptr = buf;

		*((unsigned short*)buf) = htons(va->vh);
		buf += 2;

		ldfv = (struct ListenerDeclarationFirstValue*)va->firstValue;
		memcpy(buf, ldfv->sid.ethAddr, 6);
		buf += 6;

		*((unsigned short*)buf) = htons(ldfv->sid.unique_id);
		buf += 2;

		for (vector_encoded = 0, three = 0, i = 0; i < numofval; i++) {
			if (three == 0) {
				vector_encoded = 0;
				vector_encoded += va->vec.three_events[i] * 36;
			}
			if (three == 1) {
				vector_encoded += va->vec.three_events[i] * 6;
			}
			if (three == 2) {
				vector_encoded += va->vec.three_events[i];
				*buf = vector_encoded;
				buf += 1;

				three = 0;
				continue;
			}
			three++;
		}
		if (three != 0) {
			*buf = vector_encoded;
			buf += 1;
		}
		for (vector_encoded = 0, four = 0, i = 0; i < numofval; i++) {
			if (four == 0) {
				vector_encoded = 0;
				vector_encoded += va->vec.four_events[i] * 64;
			}
			if (four == 1) {
				vector_encoded += va->vec.four_events[i] * 16;
			}
			if (four == 2) {
				vector_encoded += va->vec.four_events[i] * 4;
			}
			if (four == 3) {
				vector_encoded += va->vec.four_events[i];
				*buf = vector_encoded;
				buf += 1;

				four = 0;
				continue;
			}
			four++;
		}
		if (four != 0) {
			*buf = vector_encoded;
			buf += 1;
		}
	}
	if (type == 4) {
		struct vector_attribute* va_ptr;
		struct DomainFirstValue* dfv;
		unsigned int vector_bytes;

		unsigned char vector_encoded;
		unsigned int three;

		int i;

		firstLen = DOMAIN_ATTR_LENGTH;
		numofval = va->vh & 0x1FFF;

		if (va->vec.allocated < numofval) {
			free(buf);
			printf("Serialization Error - Event Number Not sufficient\n");
			return NULL;
		}

		vector_bytes = (unsigned int)((numofval + 2) / 3);
		*serialized_bytes = firstLen + vector_bytes + 2;
		buf = (unsigned char*)malloc(firstLen + vector_bytes + 2);
		origin_ptr = buf;

		*((unsigned short*)buf) = htons(va->vh);
		buf += 2;

		dfv = (struct DomainFirstValue*)va->firstValue;

		*buf = dfv->classId;
		buf += 1;

		*buf = dfv->priority;
		buf += 1;

		*((unsigned short*)buf) = htons(dfv->vlan_id);
		buf += 2;

		for (vector_encoded = 0, three = 0, i = 0; i < numofval; i++) {
			if (three == 0) {
				vector_encoded = 0;
				vector_encoded += va->vec.three_events[i] * 36;
			}
			if (three == 1) {
				vector_encoded += va->vec.three_events[i] * 6;
			}
			if (three == 2) {
				vector_encoded += va->vec.three_events[i];
				*buf = vector_encoded;
				buf += 1;

				three = 0;
				continue;
			}
			three++;
		}
		if (three != 0) {
			*buf = vector_encoded;
			buf += 1;
		}
	}
	if (buf != NULL) {
		return origin_ptr;
	}
	return NULL;
}

struct message* buildDomainMsg(unsigned char classId, unsigned char priority, unsigned short vlan_id, unsigned char* event) {
	unsigned char* ethAddr1, * ethAddr2;
	struct message* msg = (struct message*)malloc(sizeof(struct message));
	struct DomainFirstValue* dfv = (struct DomainFirstValue*)malloc(sizeof(struct DomainFirstValue));

	dfv->classId = classId;
	dfv->priority = priority;
	dfv->vlan_id = vlan_id;

	msg->attrType = 4;
	msg->attributeLength = DOMAIN_ATTR_LENGTH;
	msg->va.vh = ((0 << 13) + 1);
	msg->va.firstValue = (unsigned int)dfv;
	msg->va.next = NULL;
	msg->va.vec.three_events = event;
	msg->va.vec.allocated = 1;
	msg->endMark = 0;
	msg->next = NULL;

	return msg;
}



int main(int argc, char* argv[]) {
	struct message* msg;
	struct mrpdu* mrp_frame;
	unsigned char vectors[] = { 2 };
	unsigned char buffer[1500];
	unsigned int received = 0;
	unsigned char classId;
	unsigned char priority;
	unsigned short vlan_id;
	interface = strdup(argv[1]);
	classId = atoi(argv[2]);
	priority = atoi(argv[3]);
	vlan_id = atoi(argv[4]);
	vectors[0] = atoi(argv[5]);
	mrpd_init_protocol_socket(0x22EA, &msrp_sock, MSRP_ADDR);


	msg = buildDomainMsg(classId, priority, vlan_id, vectors);
	sendMsrp(msg);
	free(msg);

	received = recv(msrp_sock, buffer, 1500, 0);
	printf("MSRP Received\n");
	mrp_frame = processMsrp(buffer + 14);

	free(mrp_frame);

	close(msrp_sock);
	return 0;
}

void sendMsrp(struct message* msg) {
	unsigned char* msgbuf, * msgbuf_wrptr;
	int msgLength = 0;
	int bytes = 0;
	struct eth_header* eh;
	struct mrpdu* mrp;

	msgbuf = (unsigned char*)malloc(2000);
	if (msgbuf == NULL) {
		return;
	}

	memset(msgbuf, 0, 2000);
	msgbuf_wrptr = msgbuf;

	eh = (struct eth_header*)msgbuf_wrptr;

	eh->etherType = htons(0x22EA);

	memcpy(eh->destaddr, MSRP_ADDR, sizeof(eh->destaddr));
	memcpy(eh->srcaddr, STATION_ADDR, sizeof(eh->srcaddr));

	msgbuf_wrptr += sizeof(struct eth_header);

	mrp = (struct mrpdu*)msgbuf_wrptr;

	mrp->protocolVersion = 0;

	msgbuf_wrptr++;

	{
		unsigned char* serialized_va;
		unsigned int serialized_bytes;

		struct message* msg_ptr;

		msg_ptr = (struct message*)msgbuf_wrptr;
		msg_ptr->attrType = msg->attrType;
		msg_ptr->attributeLength = msg->attributeLength;

		msgbuf_wrptr += 4;

		serialized_va = serialize(&msg->va, msg->attrType, &serialized_bytes);

		memcpy(msgbuf_wrptr, serialized_va, serialized_bytes);
		msg->attributeListLength = serialized_bytes + 2;
		msg_ptr->attributeListLength = htons(msg->attributeListLength);

		free(serialized_va);
		msgbuf_wrptr += serialized_bytes;

		*((unsigned short*)msgbuf_wrptr) = 0x0000; // EndMark
		msgbuf_wrptr += 2;
	}

	memset(msgbuf_wrptr, 0, 2); // mrpdu EndMark
	msgbuf_wrptr += 2;

	bytes = mrpd_send(msrp_sock, msgbuf, (int)(msgbuf_wrptr - msgbuf), 0);
	free(msgbuf);
}

struct mrpdu* processMsrp(unsigned char* data) {
	unsigned char* ptr;
	struct message* msg;
	struct talkerAdvertiseFirstValue* tafv;
	struct talkerFailedFirstValue* tffv;
	struct ListenerDeclarationFirstValue* ldfv;
	struct DomainFirstValue* dfv;
	unsigned int numofval;
	unsigned int vector_bytes;
	struct mrpdu* mrp_frame = (struct mrpdu*)malloc(sizeof(struct mrpdu));

	ptr = data;

	if (*ptr != 0) {
		printf("Error - ProtocolVersion is Not 0\n");
		return NULL;
	}
	mrp_frame->protocolVersion = *ptr;
	ptr += 1;

	msg = (struct message*)ptr;

	mrp_frame->msg.attrType = msg->attrType;
	mrp_frame->msg.attributeLength = msg->attributeLength;
	mrp_frame->msg.attributeListLength = htons(msg->attributeListLength);

	ptr += 4;

	switch (msg->attrType) {
	case 1:

		if (msg->attributeLength != TALKER_ADVERTISE_ATTR_LENGTH) {
			printf("Error - Wrong Attribute Length\n");
			free(mrp_frame);
			return NULL;
		}
		mrp_frame->msg.va.vh = htons(*((unsigned short*)ptr));
		numofval = (mrp_frame->msg.va.vh & 0x1FFF);
		if (numofval == 0) {
			printf("Error - Number of Values is 0\n");
			free(mrp_frame);
			return NULL;
		}
		vector_bytes = (numofval + 2) / 3;


		ptr += 2;

		tafv = (struct talkerAdvertiseFirstValue*)malloc(sizeof(struct talkerAdvertiseFirstValue));
		mrp_frame->msg.va.firstValue = (unsigned int)tafv;

		memcpy(tafv->sid.ethAddr, ptr, 6);
		ptr += 6;

		tafv->sid.unique_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		memcpy(tafv->dfp.dstAddr, ptr, 6);
		ptr += 6;

		tafv->dfp.vlan_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		tafv->ts.max_frame_size = htons(*((unsigned short*)ptr));
		ptr += 2;

		tafv->ts.max_interval = htons(*((unsigned short*)ptr));
		ptr += 2;

		tafv->par = *ptr;
		ptr += 1;

		tafv->accumulated_latency = htonl(*((unsigned int*)ptr));
		ptr += 4;

		{
			int i, j;
			unsigned char value;
			unsigned char* vectors = (unsigned char*)malloc(vector_bytes);
			for (j = 0, i = 0; i < numofval; i++, j = (j + 1) % 3) {
				if (j == 0) {
					value = (*ptr) & 0xFF;
					ptr++;
					vectors[i] = (value / 36);
					value = value % 36;
				}
				if (j == 1) {
					vectors[i] = (value / 6);
					value = value % 6;
				}
				if (j == 2) {
					vectors[i] = value;
				}
			}
			mrp_frame->msg.va.vec.three_events = vectors;
			mrp_frame->msg.va.vec.allocated = numofval;
		}
		break;
	case 2:
		if (msg->attributeLength != TALKER_FAILED_ATTR_LENGTH) {
			printf("Error - Wrong Attribute Length\n");
			free(mrp_frame);
			return NULL;
		}
		mrp_frame->msg.va.vh = htons(*((unsigned short*)ptr));
		numofval = (mrp_frame->msg.va.vh & 0x1FFF);
		if (numofval == 0) {
			printf("Error - Number of Values is 0\n");
			free(mrp_frame);
			return NULL;
		}
		vector_bytes = (numofval + 2) / 3;


		ptr += 2;

		tffv = (struct talkerFailedFirstValue*)malloc(sizeof(struct talkerFailedFirstValue));
		mrp_frame->msg.va.firstValue = (unsigned int)tffv;

		memcpy(tffv->sid.ethAddr, ptr, 6);
		ptr += 6;

		tffv->sid.unique_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		memcpy(tffv->dfp.dstAddr, ptr, 6);
		ptr += 6;

		tffv->dfp.vlan_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		tffv->ts.max_frame_size = htons(*((unsigned short*)ptr));
		ptr += 2;

		tffv->ts.max_interval = htons(*((unsigned short*)ptr));
		ptr += 2;

		tffv->par = *ptr;
		ptr += 1;

		tffv->accumulated_latency = htonl(*((unsigned int*)ptr));
		ptr += 4;

		memcpy(tffv->f_info.system_id, ptr, 8);
		ptr += 8;

		tffv->f_info.f_code = *ptr;
		ptr += 1;

		{
			int i, j;
			unsigned char value;
			unsigned char* vectors = (unsigned char*)malloc(vector_bytes);
			for (j = 0, i = 0; i < numofval; i++, j = (j + 1) % 3) {
				if (j == 0) {
					value = (*ptr) & 0xFF;
					ptr++;
					vectors[i] = (value / 36);
					value = value % 36;
				}
				if (j == 1) {
					vectors[i] = (value / 6);
					value = value % 6;
				}
				if (j == 2) {
					vectors[i] = value;
				}
			}
			mrp_frame->msg.va.vec.three_events = vectors;
			mrp_frame->msg.va.vec.allocated = numofval;
		}

		break;
	case 3:
		if (msg->attributeLength != LISTENER_DECLARATION_ATTR_LENGTH) {
			printf("Error - Wrong Attribute Length\n");
			free(mrp_frame);
			return NULL;
		}
		mrp_frame->msg.va.vh = htons(*((unsigned short*)ptr));
		numofval = (mrp_frame->msg.va.vh & 0x1FFF);
		if (numofval == 0) {
			printf("Error - Number of Values is 0\n");
			free(mrp_frame);
			return NULL;
		}
		vector_bytes = ((numofval + 2) / 3) + ((numofval + 3) / 4);


		ptr += 2;

		ldfv = (struct ListenerDeclarationFirstValue*)malloc(sizeof(struct ListenerDeclarationFirstValue));
		mrp_frame->msg.va.firstValue = (unsigned int)ldfv;

		memcpy(ldfv->sid.ethAddr, ptr, 6);
		ptr += 6;

		ldfv->sid.unique_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		{
			int i, j;
			unsigned char value;
			unsigned char* vectors = (unsigned char*)malloc(vector_bytes);
			for (j = 0, i = 0; i < numofval; i++, j = (j + 1) % 3) {
				if (j == 0) {
					value = (*ptr) & 0xFF;
					ptr++;
					vectors[i] = (value / 36);
					value = value % 36;
				}
				if (j == 1) {
					vectors[i] = (value / 6);
					value = value % 6;
				}
				if (j == 2) {
					vectors[i] = value;
				}
			}
			mrp_frame->msg.va.vec.three_events = vectors;
			mrp_frame->msg.va.vec.allocated = numofval;
		}

		{
			int i, j;
			unsigned char value;
			unsigned char* vectors = (unsigned char*)malloc(vector_bytes);
			for (j = 0, i = 0; i < numofval; i++, j = (j + 1) % 4) {
				if (j == 0) {
					value = (*ptr) & 0xFF;
					ptr++;
					vectors[i] = value >> 6;
					value = value & 0x3F;
				}
				if (j == 1) {
					vectors[i] = value >> 4;
					value = value & 0xF;
				}
				if (j == 2) {
					vectors[i] = value >> 2;
					value = value & 0x3;
				}
				if (j == 3) {
					vectors[i] = value;
				}
			}
			mrp_frame->msg.va.vec.four_events = vectors;
		}

		break;
	case 4:

		if (msg->attributeLength != DOMAIN_ATTR_LENGTH) {
			printf("Error - Wrong Attribute Length\n");
			free(mrp_frame);
			return NULL;
		}
		mrp_frame->msg.va.vh = htons(*((unsigned short*)ptr));
		numofval = (mrp_frame->msg.va.vh & 0x1FFF);
		if (numofval == 0) {
			printf("Error - Number of Values is 0\n");
			free(mrp_frame);
			return NULL;
		}
		vector_bytes = (numofval + 2) / 3;


		ptr += 2;

		dfv = (struct DomainFirstValue*)malloc(sizeof(struct DomainFirstValue));
		mrp_frame->msg.va.firstValue = (unsigned int)dfv;

		dfv->classId = *ptr;
		ptr += 1;

		dfv->priority = *ptr;
		ptr += 1;

		dfv->vlan_id = htons(*((unsigned short*)ptr));
		ptr += 2;

		{
			int i, j;
			unsigned char value;
			unsigned char* vectors = (unsigned char*)malloc(vector_bytes);
			for (j = 0, i = 0; i < numofval; i++, j = (j + 1) % 3) {
				if (j == 0) {
					value = (*ptr) & 0xFF;
					ptr++;
					vectors[i] = (value / 36);
					value = value % 36;
				}
				if (j == 1) {
					vectors[i] = (value / 6);
					value = value % 6;
				}
				if (j == 2) {
					vectors[i] = value;
				}
			}
			mrp_frame->msg.va.vec.three_events = vectors;
			mrp_frame->msg.va.vec.allocated = numofval;
		}
		break;
	default:
		printf("Error - Wrong Attribute Type\n");
		free(mrp_frame);
		return NULL;
	}

	if (*((unsigned int*)ptr) != 0) {
		printf("Wrong EndMark\n");
		free(mrp_frame->msg.va.vec.three_events);
		if (mrp_frame->msg.attrType == 3) {
			free(mrp_frame->msg.va.vec.four_events);
		}
		free((void*)(mrp_frame->msg.va.firstValue));
		free(mrp_frame);
		return NULL;
	}

	return mrp_frame;
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

	multicast_req.mr_ifindex = if_request.ifr_ifindex;
	multicast_req.mr_type = PACKET_MR_MULTICAST;
	multicast_req.mr_alen = 6;
	memcpy(multicast_req.mr_address, multicast_addr, 6);

	rc = setsockopt(lsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		&multicast_req, sizeof(multicast_req));
	if (0 != rc) {
		close(lsock);
		return -1;
	}

	*sock = lsock;

	return 0;
}

