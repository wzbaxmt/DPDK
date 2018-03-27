#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <arpa/inet.h> 


/*
 * 为本地DPDK端代码
 * 主要为与业务无关的代码
*/
#include <stdio.h>
#include "func.h"

#define SOCKET_LOG_PATH	"/var/log/socket_log.log"

#define true	1	//报文需要处理
#define false	0	//不需要处理
#define IP_PROTOCOL 0x0008 //实际应该是0800大小端未转换
#define MAC_LEN		12
#define L2_LEN		14
#define IP_PROTO_ADDR	23
#define aes_cbc 0x01
#define sm4_ecb 0x06

#define pass 0x00
#define encrypt 0x01
#define decrypt 0x02

void printHex(char *data, int data_len, int padding_len, char *pt_mark)
{ 
	int i = 0;
	printf("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len + padding_len); i++)
	{
		if (0 == (i % 16) && i != 0)
			printf("[%d]\n", i / 16);
		printf("%02x ", data[i] & 0xFF);
	}
	printf("\n");
}

unsigned long read_uc_dat(unsigned char **p_conf, unsigned char number)
{
	unsigned char *ptemp;
	unsigned long dlong = 0;
	int i;
	if ((number < 1) || (number > 4))
	{
		printf("Error! number %d not right", number);
		return -1;
	}
	ptemp = *p_conf;
	for (i = 0; i < number; i++)
	{
		dlong = (dlong << 8) + *ptemp;
		ptemp++;
	}
	*p_conf += number;
	return dlong;
}

int socket_syslog_write(char *strto)
{
	FILE *fd = NULL;
	
	if(NULL == (fd = fopen(SOCKET_LOG_PATH,"a+")))
	{
		printf("fopen /var/log/socket_log.log error!\n");
		return -1;
	}
	fputs(strto, fd);
	fclose(fd);
	return 0;
}

int socket_syslog_write_hex(char *data, int data_len, int padding_len, char *strto)
{
	FILE *fd = NULL;
	int i;
	if(NULL == (fd = fopen(SOCKET_LOG_PATH,"a+")))
	{
		printf("fopen /var/log/socket_log.log error!\n");
		return -1;
	}
	fprintf(fd, "[%s]length=%d:%d;Data Content:\n", strto, data_len, padding_len);

	for (i = 0; i < (data_len + padding_len); i++)
	{
		if (0 == (i % 16) && i != 0)
			fprintf(fd, "[%d]\n", i / 16);
		fprintf(fd, "%02x ", data[i] & 0xFF);
	}
	fprintf(fd, "\n");
	fclose(fd);
	return 0;
}

/*readline函数实现*/
int readline(int fd, char *vptr, size_t maxlen)
{
	int	n, rc;
	char	c, *ptr;

	ptr = vptr;
	for (n = 0; n < maxlen; n++) {
		if ( (rc = read(fd, &c,1)) == 1) {
			*ptr++ = c;
		} 
	}

	*ptr = 0;	/* null terminate like fgets() */
	return(n);
}

/*=======================================================================*/


int pkt_filter(struct rte_mbuf *m)
{
	struct ipv4_hdr *iphdr;
	uint32_t dest_addr;
	unsigned short type;
	memcpy(&type, (m->buf_addr + m->data_off + MAC_LEN), 2);
	printf("type = %04x\n",type);
	if(type == IP_PROTOCOL)//暂时只处理IP报文
	{
		iphdr = (struct ipv4_hdr *)(m->buf_addr + m->data_off + L2_LEN);
		if(IPPROTO_TCP == iphdr->next_proto_id || IPPROTO_UDP == iphdr->next_proto_id)//只处理TCP和UDP报文
		{
			printf("buf_addr = %p, data_off = %d, pkt_len = %d, data_len = %d, buf_len = %d\n"
				,m->buf_addr,m->data_off,m->pkt_len,m->data_len,m->buf_len);
			if(IPPROTO_TCP == iphdr->next_proto_id)//处理TCP报文
			{
				printHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
				struct tcp_hdr *tcphdr;
				tcphdr = (struct tcp_hdr *)(m->buf_addr + m->data_off + L2_LEN + (iphdr->version_ihl&0x0f) * 4);
				printHex(tcphdr, m->data_len - L2_LEN - (iphdr->version_ihl&0x0f) * 4, 0, "TCP packet");
				//printf("tcphdr->data_off >> 4 = %x\n",tcphdr->data_off >> 4);
				int data_len = m->data_len - L2_LEN - (iphdr->version_ihl&0x0f) * 4 - (tcphdr->data_off >> 4) *4;
				char* data_org = (void *)tcphdr + (tcphdr->data_off >> 4) *4;
				printHex(data_org, data_len, 0, "TCP data");
			}
			else//处理UDP报文
			{
				printHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
				struct udp_hdr *udphdr;
				udphdr = (struct udp_hdr *)(m->buf_addr + m->data_off + L2_LEN + (iphdr->version_ihl&0x0f) * 4);
				printHex(udphdr, m->data_len - L2_LEN - (iphdr->version_ihl&0x0f) * 4, 0, "UDP packet");
				int data_len = m->data_len - L2_LEN - (iphdr->version_ihl&0x0f) * 4 - 8;
				char* data_org = (void *)udphdr + 8;
				printHex(data_org, data_len, 0, "UDP data");
			}
		}
	}
	
	return true;
}


