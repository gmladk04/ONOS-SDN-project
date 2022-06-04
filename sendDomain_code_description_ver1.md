# SendDomain.c code description ver.1

## Receiving WSA & IPv6 configuration

### Ethernet packet parsing

- ptr 필요한 만큼 이동해서 parsing
- wireshark WAVE packet 모양 참고

```c
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
	//ipv6_prefix
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
```

### IPv6 configuration

- `std::format` 이용해서 자동으로 xterm 내에서 자동으로 ipv6 packet 조립함
    
    ```c
    /*default gateway + device*/
    std::string default_gw_string = string_format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", default_gw[0], default_gw[1], default_gw[2], default_gw[3], default_gw[4], default_gw[5], default_gw[6], ipv6_prefix[7], default_gw[8], default_gw[9], default_gw[10], default_gw[11], default_gw[12], default_gw[13], default_gw[14], default_gw[15]);
    
    	std::string str = "ip -6 route add default via ";
    	str = str + default_gw_string;
    
    	std::string dev = " dev ";
    	std::string interface_str (interface);
    	str = str + dev;
    	str = str + interface_str;
    	
    	system(str.c_str());
    ```
    
    ```c
    /* ip -6 neigh add <IPv6 address> lladdr <link-layer address> dev <device>*/
    	std::string str_neigh = "ip -6 neigh add ";
    	str_neigh = str_neigh + default_gw_string;
    
    	std::string str_lladdr = " lladdr ";
    	str_neigh = str_neigh + str_lladdr;
    	str_neigh = str_neigh + default_gw_mac_string;
    	str_neigh = str_neigh + dev;
    	str_neigh = str_neigh + interface_str;
    
    	system(str_neigh.c_str());
    ```
    
- parsing한 값 들 붙여서 string 으로 만들어줌

---

## Make NS message

### Define UDP socket

```c
int udp_sock;

mrpd_init_protocol_socket(0x86DD, &udp_sock, MSRP_ADDR);
```

### Define Header structrue

> IPv6 header structure
> 

```c
struct ipv6_header {
	unsigned int ver_tc_flow_label;
	unsigned short payload_length;
	unsigned char nh;
	unsigned char hop_limit;
	unsigned char destaddr[16];
	unsigned char sourceaddr[16];
	};
```
![Untitled](https://user-images.githubusercontent.com/48545220/171992599-b2517465-f9cc-4080-bad6-1352e13bc721.png)


> UDP header structrue
> 

```c
struct udp_header {
	unsigned short sourceport;
	unsigned short destinationport;
	unsigned short udp_length;
	unsigned short udp_checksum;
};
```
![Untitled 1](https://user-images.githubusercontent.com/48545220/171992604-959e3d5a-7947-4d19-a6e0-b9e454f84708.png)

> NS message header structure
> 

```c
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
```

---

## Make and Send NS message

1. buffer 만들어서 뒤에서 부터 씀
    - `buf_ptr -= sizeof(unh);`
2. packet 다 채웠으면 `send`
    - `send(udp_sock, buf_ptr, data_lend, 0);`

```c
char target_addr[16] = {0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
char src_addr[16] = {0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
char dst_addr[16]={ 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x0, 0x0, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1};
char lladdr[6]={0x12, 0x12, 0x12,0x12, 0x12, 0x12};

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
```

![Untitled 2](https://user-images.githubusercontent.com/48545220/171992614-3e35662a-b08a-45d9-952c-d751328b8a2f.png)
![Untitled 3](https://user-images.githubusercontent.com/48545220/171992618-af8d89b8-73d5-4495-a736-320e5bf55220.png)


## Receiving & Processing NA message

- sending NS 과정을 모두 수행하고 나서 NS가 수행되어야 하므로 `send` function 뒤에 process NA를 한다.
    - `processNA((unsigned char *)buf_ptr);`
- Receiving WSA message와 유사하게 `ptr` 이용하여 parsing 수행
    
    ```c
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
    }
    ```
    

---

## Result

![Untitled 4](https://user-images.githubusercontent.com/48545220/171992620-ea46e4f4-4d46-44f5-93c4-a58f26a9e7f0.png)


---

## Reference
