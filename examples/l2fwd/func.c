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
#include "sm4.h"
#include "protocol.h"

#define SOCKET_LOG_PATH "/var/log/socket_log.log"

#define true 1			   //报文需要处理
#define false 0			   //不需要处理
#define IP_PROTOCOL 0x0008 //实际应该是0800大小端未转换
#define MAC_LEN 12
#define L2_LEN 14
#define IP_PROTO_ADDR 23
#define aes_cbc 0x01
#define sm4_ecb 0x06

#define pass 0x00
#define encrypt 0x01
#define decrypt 0x02
typedef char BYTE;
typedef unsigned short __sum16;
typedef unsigned short u16;
typedef unsigned int u32;

#define ENC_OUT 1
#define DEC_IN 0

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

	if (NULL == (fd = fopen(SOCKET_LOG_PATH, "a+")))
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
	if (NULL == (fd = fopen(SOCKET_LOG_PATH, "a+")))
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
	int n, rc;
	char c, *ptr;

	ptr = vptr;
	for (n = 0; n < maxlen; n++)
	{
		if ((rc = read(fd, &c, 1)) == 1)
		{
			*ptr++ = c;
		}
	}

	*ptr = 0; /* null terminate like fgets() */
	return (n);
}

/*=======================================================================*/
/*************调用国密算法**************/
int SM4ECBEncrypt(BYTE *dest, BYTE *source, int sourceLen, BYTE *key)
{
	sm4_context ctx;

	sm4_setkey_enc(&ctx, key);
	sm4_crypt_ecb(&ctx, 1, sourceLen, source, dest);

	return 0;
}

int SM4ECBDecrypt(BYTE *dest, BYTE *source, int sourceLen, BYTE *key)
{
	sm4_context ctx;

	sm4_setkey_dec(&ctx, key);
	sm4_crypt_ecb(&ctx, 0, sourceLen, source, dest);

	return 0;
}

//补齐至16字节（128位）
static char padding_fill(int data_len)
{
	char tmp_len = 0;
	tmp_len = data_len % 16;
	tmp_len = (tmp_len == 0 ? 16 : 16 - tmp_len);
	return tmp_len;
}

static int do_sm4_encrypt(char *data_in, int data_len, int enc_dec, char *key_in, int key_len, char *result)
{
	if (data_len % 16 != 0 && enc_dec == DEC_IN) //流入的需解密的报文必须是16字节的整数倍
	{
		printf("do_sm4_encrypt data_len%16 != 0  && enc_dec == DEC_IN !\n");
		return -1;
	}

	unsigned int ret;
	char padding_len;
	char buf[1518] = {0};

	if (DEC_IN == enc_dec)
		padding_len = 0;
	else
		padding_len = padding_fill(data_len);

	memset(buf, padding_len, (data_len + padding_len)); //填充字节为补齐的位数,pks-7
	memcpy(buf, data_in, data_len);
	if (enc_dec) //1 加密
	{
		//加密
		ret = SM4ECBEncrypt(result, buf, (data_len + padding_len), key_in);
		printf("SM4 encrypt success***********************\n");
#ifdef DEBUG
		printHex(buf, data_len, padding_len, "SM4ECBEncrypt buf is");
#endif
	}
	else //0 解密
	{
		//解密
		ret = SM4ECBDecrypt(result, buf, (data_len + padding_len), key_in);
		printf("SM4 decrypt success***********************\n");
#ifdef DEBUG
		printHex(buf, data_len, padding_len, "SM4ECBDecrypt buf is");
#endif
	}

	return (data_len + padding_len);
}
//检测填充的字节是否除最后一个字节外都为0
static char padding_check(char *data, int len)
{
	char ex;
	int flag = 0, i = 0;

	ex = data[len - 1]; //数据部分的最后一位
	if (ex < 1 || ex > 16)
		return 0;

	for (i = 1; i < ex; i++)
	{
		if (ex == data[len - i - 1])
		{
			;
		}
		else
		{
			flag = 1;
			break;
		}
	}
	if (flag == 0)
		return ex;
	else
		return 0;
}

/*计算校验和*/
static unsigned short int chksum_t(void *dataptr, unsigned short int len)
{
#if 0
  printHex(dataptr, len, 0, "chksum_t");
#endif
	unsigned int acc;
	unsigned short int src;
	unsigned char *octetptr;

	acc = 0;
	octetptr = (unsigned char *)dataptr;

	while (len > 1)
	{
		src = (*octetptr) << 8;
		octetptr++;
		src |= (*octetptr);
		octetptr++;
		acc += src;
		len -= 2;
	}

	if (len > 0)
	{
		src = (*octetptr) << 8;
		acc += src;
	}

	acc = (acc >> 16) + (acc & 0x0000ffffUL);
	if ((acc & 0xffff0000UL) != 0)
	{
		acc = (acc >> 16) + (acc & 0x0000ffffUL);
	}

	src = (unsigned short int)acc;
	return ~src;
}
/*计算TCP UDP校验和*/
static u16 get_tcp_udp_checksum(u32 saddr, u32 daddr, u_short len, char ptcl, void *sbuf)
{
	struct psd_header psdh;
	char buf[2048] = {0};
	void *p;
	u16 sum = 0;
	psdh.saddr = saddr;
	psdh.daddr = daddr;
	psdh.mbz = 0x0;
	psdh.ptcl = ptcl;
	psdh.tcpl = htons(len);

	p = (void *)buf;

	memcpy(p, &psdh, sizeof(struct psd_header));
	memcpy(p + sizeof(struct psd_header), sbuf, len);

	sum = chksum_t(p, len + sizeof(struct psd_header));
	return sum;
}

static int enc_msg_check(void *enc_data, int enc_len)
{
#if 1 //代码功能测试通过，待设备端稳定后启用
	__sum16 rcv_crc;
	__sum16 new_crc;
	unsigned short new_msglen;
	struct encHeader *enc_header;
	enc_header = enc_data;
	rcv_crc = enc_header->CRC;
	enc_header->CRC = 0x0000;
	new_crc = htons(chksum_t(enc_data, enc_len)); //计算校验和，算法与设备端一致
	new_msglen = enc_len;
	if (new_msglen == htons(enc_header->msglen) && new_crc == rcv_crc)
	{
#ifdef DEBUG
		printf("rcv_crc %x,new_crc %x\n", rcv_crc, new_crc);
		printf("new_msglen %d , enc_header->msglen %d\n", new_msglen, htons(enc_header->msglen));
#endif
		return 1;
	}
	else
	{
		printHex(enc_header, sizeof(struct encHeader), 0, "enc_msg_check");
		printf("rcv_crc %x,new_crc %x\n", rcv_crc, new_crc);
		printf("new_msglen %d , enc_header->msglen %d\n", new_msglen, htons(enc_header->msglen));
		return 0;
	}
#else
	return 1;
#endif
}


int pkt_filter(struct rte_mbuf *m)
{
	struct ipv4_hdr *iphdr;
	uint32_t dest_addr;
	unsigned short type;
	memcpy(&type, (m->buf_addr + m->data_off + MAC_LEN), 2);
	//printf("type = %04x\n", type);
	if (type == IP_PROTOCOL) //暂时只处理IP报文
	{
		char *data_origin = NULL;
		int data_len = 0;
		char key[32] = {0};
		int key_len = 0;
		char result[2000] = {0};
		int result_len = 0;
		int padding_len = 0;
		struct encHeader enc_header = {0};
		struct tcp_hdr *tcphdr = NULL;
		struct udp_hdr *udphdr = NULL;
		
		iphdr = (struct ipv4_hdr *)(m->buf_addr + m->data_off + L2_LEN);
		printf("buf_addr = %p, data_off = %d, pkt_len = %d, data_len = %d, buf_len = %d\n", m->buf_addr, m->data_off, m->pkt_len, m->data_len, m->buf_len);
		struct ip_struct hD = {0};
		memcpy(hD.sMac, m->buf_addr + m->data_off + 6, 6);
		memcpy(hD.dMac, m->buf_addr + m->data_off, 6);
		memcpy(hD.sIP, &iphdr->src_addr, 4);
		memcpy(hD.dIP, &iphdr->dst_addr, 4);
		printHex(&hD, sizeof(hD), 0, "hD");
		if (IPPROTO_TCP == iphdr->next_proto_id) //处理TCP报文
		{
			printHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
			tcphdr = (struct tcp_hdr *)(m->buf_addr + m->data_off + L2_LEN + (iphdr->version_ihl & 0x0f) * 4);
			printHex(tcphdr, m->data_len - L2_LEN - (iphdr->version_ihl & 0x0f) * 4, 0, "TCP packet");
			data_len = m->data_len - L2_LEN - (iphdr->version_ihl & 0x0f) * 4 - (tcphdr->data_off >> 4) * 4;
			data_origin = (void *)tcphdr + (tcphdr->data_off >> 4) * 4;
			printHex(data_origin, data_len, 0, "TCP data");
			memcpy(hD.sPort, &tcphdr->src_port, 2);
			memcpy(hD.dPort, &tcphdr->dst_port, 2);
		}
		else if (IPPROTO_UDP == iphdr->next_proto_id) //处理UDP报文
		{
			printHex((m->buf_addr + m->data_off), m->data_len, 0, "packet");
			udphdr = (struct udp_hdr *)(m->buf_addr + m->data_off + L2_LEN + (iphdr->version_ihl & 0x0f) * 4);
			printHex(udphdr, m->data_len - L2_LEN - (iphdr->version_ihl & 0x0f) * 4, 0, "UDP packet");
			data_len = m->data_len - L2_LEN - (iphdr->version_ihl & 0x0f) * 4 - 8;
			data_origin = (void *)udphdr + 8;
			printHex(data_origin, data_len, 0, "UDP data");
			memcpy(hD.sPort, &udphdr->src_port, 2);
			memcpy(hD.dPort, &udphdr->dst_port, 2);
		}
		else //其他IP协议，暂不处理
		{
			return true;
		}

		if (*data_origin == 0xff) //初步判断是加密报文
		{ 
			struct encHeader *enc_header = (struct encHeader *)data_origin;
			if (!enc_msg_check(data_origin, data_len)) //不是加密报文
			{
				printHex(data_origin, data_len, 0, "not enc packet");
			}
			else //是加密报文
			{
				//对应加密头能不能取出密钥,能取出密钥，则需解密
				if (apply_config(&hD, DEC_IN, enc_header, key, data_len))
				{
					switch (enc_header->encType)
					{
					case aes_cbc:
						//result_len = do_aes_encrypt(data_origin + sizeof(struct encHeader), data_len - sizeof(struct encHeader), DEC_IN, &key, key_len, "a", 0, result);
						break;
					case sm4_ecb:
						result_len = do_sm4_encrypt(data_origin + sizeof(struct encHeader), data_len - sizeof(struct encHeader), DEC_IN, &key, key_len, result);
						break;
					default:
						printf("%d Encryption algorithms are not supported yet!!\n", enc_header->encType);
						result_len = -1;
						break;
					}
					if (result_len < 0)
					{
						printf("tcp do_%x_encrypt dec fail!!\n", enc_header->encType);
						return true;
					}
					else
					{
						//填充检查，检验填充了几位
						padding_len = padding_check(result, result_len);
						if (!padding_len) //解密后数据肯定有扩充，没有则是出错报文
						{
							printHex(result, result_len, 0, "padding_len error");
							return true;
						}
						else
						{
							memcpy(data_origin, result, result_len - padding_len);
							m->data_len = m->data_len - padding_len - sizeof(struct encHeader);

							iphdr->total_length = iphdr->total_length - padding_len - sizeof(struct encHeader); //remove padding from length
							iphdr->hdr_checksum = 0;
							iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
							if (IPPROTO_TCP == iphdr->next_proto_id) //处理TCP报文
							{
								tcphdr->cksum = 0;
								tcphdr->cksum = htons(get_tcp_udp_checksum(iphdr->src_addr, iphdr->dst_addr, (result_len + (tcphdr->data_off >> 4) * 4 - padding_len), IPPROTO_TCP, tcphdr));
								return true; //解密完成后直接接收
							}
							else//处理UDP报文
							{
								udphdr->dgram_len = udphdr->dgram_len - padding_len - sizeof(struct encHeader);
								udphdr->dgram_cksum = 0;
								udphdr->dgram_cksum = htons(get_tcp_udp_checksum(iphdr->src_addr, iphdr->dst_addr, (result_len + 8 - padding_len), IPPROTO_UDP, udphdr));
								return true; //解密完成后直接接收
							}
						}
					}
				}
			}
		}
		/*****如果之前没有返回，则报文可能需要加密***/

		//对应hD能不能取出密钥
		if (apply_config(&hD, ENC_OUT, &enc_header, key, data_len)) //能取出密钥，则报文需要进行加密处理
		{
			switch (enc_header.encType)
			{
			case aes_cbc:
				//result_len = do_aes_encrypt(data_origin + sizeof(struct encHeader), data_len - sizeof(struct encHeader), DEC_IN, &key, key_len, "a", 0, result);
				break;
			case sm4_ecb:
				result_len = do_sm4_encrypt(data_origin, data_len, DEC_IN, key, key_len, result);
				break;
			default:
				printf("%d Encryption algorithms are not supported yet!!\n", enc_header.encType);
				result_len = -1;
				break;
			}
			if (result_len < 0)
			{
				printf("do_%d_encrypt enc fail!!\n", enc_header.encType);
				return true;
			}
			else
			{
				enc_header.msglen = htons(result_len + sizeof(struct encHeader));
				enc_header.CRC = 0x0000;
				memcpy(data_origin, &enc_header, sizeof(struct encHeader));
				memcpy(data_origin + sizeof(struct encHeader), result, result_len);
				enc_header.CRC = htons(chksum_t(data_origin, result_len + sizeof(struct encHeader))); //计算校验和，算法与设备端一致

				iphdr->total_length = iphdr->total_length + result_len - data_len + sizeof(struct encHeader); //remove padding from length
				iphdr->hdr_checksum = 0;
				iphdr->hdr_checksum = rte_ipv4_cksum(iphdr); //re-checksum for IP
				if (IPPROTO_TCP == iphdr->next_proto_id) //处理TCP报文
				{
					tcphdr->cksum = 0;
					tcphdr->cksum = htons(get_tcp_udp_checksum(iphdr->src_addr, iphdr->dst_addr, (result_len + (tcphdr->data_off >> 4) * 4 + sizeof(struct encHeader)), IPPROTO_TCP, tcphdr));
					return true;
				}
				else
				{
					udphdr->dgram_len = udphdr->dgram_len + (result_len - data_len) + sizeof(struct encHeader);
					udphdr->dgram_cksum = 0;
					udphdr->dgram_cksum = htons(get_tcp_udp_checksum(iphdr->src_addr, iphdr->dst_addr, (result_len + 8 + sizeof(struct encHeader)), IPPROTO_UDP, udphdr));
					return true; //解密完成后直接接收
				}
			}
		}
		else //没有匹配的规则，则不需要进一步处理了,直接返回
		{
			return true;
		}
	}
	else//非IP报文暂不处理
	{
		return true;
	}
}


