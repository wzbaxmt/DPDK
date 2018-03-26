#include <rte_mbuf.h>
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
#define IP_PROTO_ADDR	23
#define aes_cbc 0x01
#define sm4_ecb 0x06

#define pass 0x00
#define encrypt 0x01
#define decrypt 0x02


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








//hD			报文头数据
//in_out		0 接收的报文，需解密          1 发出的报文，需加密
//enc_header	加密头的指针
//key			加密密钥的指针
//pkt_len		此报文的长度
//key_len		返回值 0 无需操作 其他 加密密钥长度
static int apply_config(struct ip_struct *ip_data, int in_out, struct encHeader *enc_header, char *key, int pkt_len)
{
	int key_len = 0;
	int err = 0;
	struct ip2id_struct* pp;
	struct id2data_struct* p;
	unsigned char deviceID[DIDLen] = {0};
	unsigned char zero[6] = {0};
	
	if (ENC_OUT == in_out) //发出的报文，需要加密？
	{
		if(!hashmap_get(ip2id, ip_data->dIP, (void**)(&pp)))//发出报文目的地址与接收报文的源地址一致（ip2id存储的是接收报文信息）
		{
			memcpy(deviceID, pp->DeviceID, DIDLen);
			printHex(deviceID, DIDLen, 0, "find ip 2 deviceID");
			if(hashmap_get(id2data, deviceID, (void**)(&p)))
			{			
				printf("do not have this deviceID yet!\n");
			}
			else
			{
				int j;
				for(j = 0; j < p->config_num; j++)
				{
					if ((0 == memcmp(p->config_list + 8 + sizeof(struct config_list0) * j, zero, 4) || 0 == memcmp(p->config_list + 8 + sizeof(struct config_list0) * j, ip_data->sIP, 4)) 
					&& (0 == memcmp(p->config_list + 12 + sizeof(struct config_list0) * j, zero, 4) || 0 == memcmp(p->config_list + 12 + sizeof(struct config_list0) * j, ip_data->dIP, 4)) 
					&& (0 == memcmp(p->config_list + 28 + sizeof(struct config_list0) * j, zero, 2) || 0 == memcmp(p->config_list + 28 + sizeof(struct config_list0) * j, ip_data->sPort, 2)) 
					&& (0 == memcmp(p->config_list + 30 + sizeof(struct config_list0) * j, zero, 2) || 0 == memcmp(p->config_list + 30 + sizeof(struct config_list0) * j, ip_data->dPort, 2)) 
					&& (0 == memcmp(p->config_list + 16 + sizeof(struct config_list0) * j, zero, 6) || 0 == memcmp(p->config_list + 16 + sizeof(struct config_list0) * j, ip_data->sMac, 6)) 
					&& (0 == memcmp(p->config_list + 22 + sizeof(struct config_list0) * j, zero, 6) || 0 == memcmp(p->config_list + 22 + sizeof(struct config_list0) * j, ip_data->dMac, 6)))
					{
						//匹配是否加密，目前只匹配aes加密(0x01)
						//20180122需求增加sm4算法(0x10)
						if ((0 == memcmp(p->config_list + 4 + sizeof(struct config_list0) * j, &aes_cbc_uc, 1)) || (0 == memcmp(p->config_list + 4 + sizeof(struct config_list0) * j, &sm4_ecb_uc, 1)))
						{
							key_len = p->key_list[1].key_len;
							memcpy(key, &p->key_list[1].key_value, p->key_list[1].key_len);
							enc_header->flag = 0xff;
							memcpy(&enc_header->encType, (p->config_list + 4 + sizeof(struct config_list0) * j), 1);
							memcpy(&enc_header->keyID, &p->key_list[1].key_id, KIDLen);
							{
								if (pp->DataOut > 4294900000) //此处会有误差
								{
									pp->DataOut = 0;
								}
								pp->DataOut += pkt_len; //统计加密流出的流量
							}
							break; //跳出配置循环
						}
						else
						{
							printf("encType not support yet!\n");
							key_len = 0;
							break;
						}
					}
				}
			}
		}
	}
	else if (DEC_IN == in_out) //进来的报文，需要解密?
	{
		memcpy(deviceID,enc_header->keyID,DIDLen);		
		if(hashmap_get(id2data, deviceID, (void**)(&p)))//没找到该DeviceID，即原先不存在，则增加该节点
		{
			printf("do not have this deviceID yet!\n");
		}
		else
		{
			//填充IP2ID对应关系
			if(hashmap_get(ip2id, ip_data->sIP, (void**)(&pp)))//没找到该sIP，即原先不存在，则增加该节点
			{
				pp = (char*)calloc(sizeof(struct ip2id_struct), sizeof(char));/*分配内存空间,初始化为0*/ 
				memcpy(pp, ip_data, sizeof(struct ip2id_struct));
				memcpy(pp->DeviceID, deviceID, DIDLen);
				pp->DataIn = pkt_len;
				err = hashmap_put(ip2id, pp->sIP, pp);
			}
			else
			{
				if(pp->DataIn > 4294900000)
				{
					pp->DataIn = 0;
					printf("DataIn overflow, reset 4294900000 to 0\n");
				}
				pp->DataIn += pkt_len;
			}
			
			int i;
			for(i = 0; i < p->key_num; i++)
			{
				if (0 == memcmp(&enc_header->keyID, &p->key_list[i], 16)) //匹配到KeyID
				{
					key_len = p->key_list[i].key_len;
					memcpy(key, &p->key_list[i].key_value, p->key_list[i].key_len);
					break;
				}
			}
		}
	}
	else
	{
		printf("not support yet!\n");
	}
	return key_len;
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
		if(IPPROTO_TCP == *(char*)(m->buf_addr + m->data_off + IP_PROTO_ADDR) 
		|| IPPROTO_UDP == *(char*)(m->buf_addr + m->data_off + IP_PROTO_ADDR))//只处理TCP和UDP报文
		{
			printf("buf_addr = %p, data_off = %d, pkt_len = %d, data_len = %d, buf_len = %d\n"
				,m->buf_addr,m->data_off,m->pkt_len,m->data_len,m->buf_len);
			printkHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
			if(IPPROTO_TCP == *(char*)(m->buf_addr + m->data_off + IP_PROTO_ADDR))//处理TCP报文
			{
				

			}
			else//处理UDP报文
			{


			}
		}
	}
	
	return true;
}


