#include <rte_mbuf.h>

#define true	1	//报文需要处理
#define false	0	//不需要处理
#define IP_PROTOCOL 0x0008 //实际应该是0800大小端未转换
#define MAC_LEN		12
#define IP_PROTO_ADDR	23

/* Standard well-defined IP protocols.  */
enum {
  IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
  IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
  IPPROTO_IGMP = 2,		/* Internet Group Management Protocol	*/
  IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
  IPPROTO_TCP = 6,		/* Transmission Control Protocol	*/
  IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
  IPPROTO_PUP = 12,		/* PUP protocol				*/
  IPPROTO_UDP = 17,		/* User Datagram Protocol		*/
  IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
  IPPROTO_DCCP = 33,		/* Datagram Congestion Control Protocol */
  IPPROTO_RSVP = 46,		/* RSVP protocol			*/
  IPPROTO_GRE = 47,		/* Cisco GRE tunnels (rfc 1701,1702)	*/

  IPPROTO_IPV6	 = 41,		/* IPv6-in-IPv4 tunnelling		*/

  IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */
  IPPROTO_AH = 51,             /* Authentication Header protocol       */
  IPPROTO_BEETPH = 94,	       /* IP option pseudo header for BEET */
  IPPROTO_PIM    = 103,		/* Protocol Independent Multicast	*/

  IPPROTO_COMP   = 108,                /* Compression Header protocol */
  IPPROTO_SCTP   = 132,		/* Stream Control Transport Protocol	*/
  IPPROTO_UDPLITE = 136,	/* UDP-Lite (RFC 3828)			*/

  IPPROTO_RAW	 = 255,		/* Raw IP packets			*/
  IPPROTO_MAX
};

//data 
//data_len + padding_len
//pt_mark 
void printkHex(char *data, int data_len, int padding_len, char* pt_mark)
{	
	int i = 0;
	printf("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len+padding_len); i ++) 
	{
		if(0 == (i%16) && i != 0)
			printf("[%d]\n",i/16);
		printf("%02x ", data[i] & 0xFF);
	}
	printf("\n");
}







/*****************************************************************************/
int pkt_filter(struct rte_mbuf *m)
{
	struct ipv4_hdr *iphdr;
	uint32_t dest_addr;
	unsigned short type;
	memcpy(&type, (m->buf_addr + m->data_off + MAC_LEN), 2);
	printf("type = %04x\n",type);
	if(type == IP_PROTOCOL)//暂时只处理IP报文
	{
		if(IPPROTO_TCP == *(char*)(m->buf_addr + m->data_off + IP_PROTO_ADDR) 
		|| IPPROTO_UDP == *(char*)(m->buf_addr + m->data_off + IP_PROTO_ADDR))//只处理TCP和UDP报文
		{
			printf("buf_addr = %p, data_off = %d, pkt_len = %d, data_len = %d, buf_len = %d\n"
				,m->buf_addr,m->data_off,m->pkt_len,m->data_len,m->buf_len);
			printkHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
		}
	}
	
	return true;
}


