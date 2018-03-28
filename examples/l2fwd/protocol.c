/*
 * 为本地DPDK端代码
 * 主要为与业务相关代码
 * 与密钥云交互功能实现
*/
#include "protocol.h"
#include <stdlib.h>

unsigned short req_id = 0;
unsigned int   last_len = 0;
unsigned char  last_msg[MaxLen];
unsigned char aes_cbc_uc = 0x01;
unsigned char sm4_ecb_uc = 0x06;


int send_msg(char *msg_addr, int msg_len)
{
	const int MAX_LINE = 1024;
	char sendline[MAX_LINE];
	bzero(&sendline , MAX_LINE);
	printHex(msg_addr, msg_len, 0, "send msg to server");
	if(msg_len != 8)
	{
		if(msg_len < MaxLen)
		{
			memcpy(last_msg, msg_addr, msg_len);
			last_len = msg_len;
		}
		else
		{
			return 1;
		}
	}
	memcpy(&sendline,msg_addr,msg_len);
	write(sockfd , msg_addr , msg_len);
	return 0;
}

unsigned char cfg_clear(char *msg_addr, unsigned short list_num)
{
	int result = 1;
	struct id2data_struct* p;
	unsigned char deviceID[DIDLen] = {0};
	
	memcpy(deviceID, msg_addr+pDID, DIDLen);
	if(hashmap_get(id2data, deviceID, (void**)(&p)))//没找到该DeviceID
	{
		result = 1;
	}
	else//找到该DeviceID
	{
		if(p->config_num != 0 && p->config_list != NULL)
		{
			p->config_num = 0;
			free(p->config_list);
			if(p->config_list != NULL)
				p->config_list = NULL;
			
			result = 0;
		}
		else if(p->config_num == 0 && p->config_list == NULL)
		{			
			result = 0;
		}
		else
		{
			result = 1;
		}	
	}
	return result;
}
unsigned char cfg_replace(char *msg_addr, unsigned short list_num)
{
	int result = 1;
	struct id2data_struct* p;
	unsigned char deviceID[DIDLen] = {0};
	
	memcpy(deviceID, msg_addr + pDID, DIDLen);
	if(hashmap_get(id2data, deviceID, (void**)(&p)))//没找到该DeviceID，即原先不存在，则增加该节点
	{
		p = (char*)calloc(sizeof(struct id2data_struct), sizeof(char));/*分配内存空间,初始化为0*/ 
		memcpy(p->DeviceID, msg_addr + pDID, DIDLen);
		p->config_num = list_num;
		p->config_list = malloc(list_num * sizeof(struct config_list0));
		memcpy(p->config_list, msg_addr + pLIST, list_num * sizeof(struct config_list0));
		result = hashmap_put(id2data, p->DeviceID, p);
	}
	else//找到该DeviceID,即原先存在，则替换原配置
	{
		if(p->config_num != 0 && p->config_list != NULL)
		{
			free(p->config_list);
			if(p->config_list != NULL)
				p->config_list = NULL;
		}
		p->config_num = list_num;
		p->config_list = malloc(list_num * sizeof(struct config_list0));
		memcpy(p->config_list, msg_addr + pLIST, list_num * sizeof(struct config_list0));
		result = 0;
	}
	return result;
}
unsigned char cfg_add(char *msg_addr, unsigned short list_num)
{
	int result = 1;
	struct id2data_struct* p;
	unsigned char deviceID[DIDLen] = {0};
	
	memcpy(deviceID, msg_addr+pDID, DIDLen);
	if(hashmap_get(id2data, deviceID, (void**)(&p)))//没找到该DeviceID，即原先不存在，则增加该节点
	{
		p = (char*)calloc(sizeof(struct id2data_struct), sizeof(char));/*分配内存空间,初始化为0*/ 
		memcpy(p->DeviceID, msg_addr + pDID, DIDLen);
		p->config_num = list_num;
		p->config_list = malloc(list_num * sizeof(struct config_list0));
		memcpy(p->config_list, msg_addr + pLIST, list_num * sizeof(struct config_list0));
		result = hashmap_put(id2data, p->DeviceID, p);
	}
	else
	{
		if(p->config_num != 0 && p->config_list != NULL)//存在该节点，且有cfg
		{
			int i,j;
			int repeat = 0;
			void *config_list;//新申请的空间指针
			config_list = (char*)calloc(((p->config_num + list_num) * sizeof(struct config_list0)), sizeof(char));//申请一块足够大的空间
			memcpy(config_list, p->config_list, p->config_num * sizeof(struct config_list0));//把原配置拷贝到新地址
			for(j = 0; j < list_num; j++)//将下发的每一个配置
			{
				for(i = 0; i < p->config_num; i++)//与原先的配置做匹配
				{
					if (0 != memcmp((config_list + 4 + sizeof(struct config_list0) * i), (msg_addr + pLIST + 4 + sizeof(struct config_list0) * j), sizeof(struct config_list0) - 4))//上个版本只匹配了源IP
					{
						memcpy(config_list + sizeof(struct config_list0) * (p->config_num + repeat), (msg_addr + pLIST + sizeof(struct config_list0) * j), sizeof(struct config_list0));
						repeat++;
					}
				}
			}
			free(p->config_list);
			if(p->config_list != NULL)
				p->config_list = NULL;
			p->config_num += repeat;
			p->config_list = config_list;
			result = 0;
			//多申请的空间将在下次free时释放
		}
		else//存在该节点，但没有cfg(只存了密钥)
		{
			p->config_num = list_num;
			p->config_list = malloc(list_num * sizeof(struct config_list0));
			memcpy(p->config_list, msg_addr + pLIST, list_num * sizeof(struct config_list0));
			result = 0;
		}
	}
	return result;
	
}
unsigned char cfg_delete(char *msg_addr, unsigned short list_num)
{
	return cfg_clear(msg_addr, list_num);
}
unsigned char cfg_change(char *msg_addr, unsigned short list_num)
{
	return cfg_add(msg_addr, list_num);
}
unsigned char key_update(char *msg_addr, unsigned short list_num)
{
	int result = 1;
	struct id2data_struct* p;
	unsigned char deviceID[DIDLen] = {0};

	memcpy(deviceID, msg_addr+pDID, DIDLen);
	if(hashmap_get(id2data, deviceID, (void**)(&p)))//没找到该DeviceID，即原先不存在，则增加该节点
	{
		p = (char*)calloc(sizeof(struct id2data_struct), sizeof(char));/*分配内存空间,初始化为0*/ 
		memcpy(p->DeviceID, msg_addr + pDID, DIDLen);
		p->key_num = list_num;
		p->config_list =NULL;
		memcpy(p->key_list, msg_addr + pLIST, sizeof(struct key_list0)*list_num);
		
		result = hashmap_put(id2data, p->DeviceID, p);
	}
	else//找到该DeviceID
	{
		int i,j,exist;
		exist = 0;
		for (j = 0; j < list_num; j++)
		{
			for (i = 0; i < 3; i++)
			{
				if (0 == memcmp(&p->key_list[i], (msg_addr + pLIST + (sizeof(struct key_list0) * j)), sizeof(struct key_list0)))
				{
					exist++; //不能存在重复密钥
					break;
				}
			}
			if(exist)
				break;
		}
		if(exist)
		{
			result = 1;
			return result;
		}
		else
		{
			if (1 == list_num)
			{
				memcpy(&p->key_list[2], &p->key_list[1], sizeof(struct key_list0)); 		//1->2
				memcpy(&p->key_list[1], &p->key_list[0], sizeof(struct key_list0));			//0->1
				memcpy(&p->key_list, (msg_addr + pLIST), sizeof(struct key_list0)); //新收到密钥放在0
			}
			else if (2 == list_num)
			{
				memcpy(&p->key_list[2], &p->key_list[0], sizeof(struct key_list0)); //0->2
				memcpy(&p->key_list[1], (msg_addr + pLIST), sizeof(struct key_list0));
				memcpy(&p->key_list[0], (msg_addr + pLIST + sizeof(struct key_list0)), sizeof(struct key_list0));
			}
			else if (3 == list_num) //3个密钥一次下发，全覆盖
			{
				memcpy(&p->key_list, (msg_addr + pLIST), (sizeof(struct key_list0) * list_num));
			}
			else //目前一个DeviceID只存3个密钥
			{
				result = 1;
			}
		}
	}
	return result;
}

unsigned char rcv_cfg(char *msg_addr, int msg_len)
{
	unsigned short	list_num;
	unsigned char	deviceID_len;
	unsigned char	op_type;
	unsigned char	result = 1;
	
	memcpy(&list_num, msg_addr + pLISTNUM, sizeof(list_num));
	if (list_num > 999 || msg_len < (16 + sizeof(struct config_list0) * list_num))
	{
		socket_syslog_write("list_num error\n");
		return 1;
	}
	
	memcpy(&deviceID_len, msg_addr + pDIDLEN, sizeof(deviceID_len));
	if (deviceID_len != DIDLen) //目前限定为DIDLen长度的DeviceID，8位
	{
		socket_syslog_write("deviceID_len error\n");
		return 1;
	}

	memcpy(&op_type, msg_addr, sizeof(op_type));
	switch(op_type)
	{
		case CLEAR:
			result = cfg_clear(msg_addr, list_num);//清空，目前与删除同
			break;
		case REPLACE:
			result = cfg_replace(msg_addr, list_num);//全量替换
			break;
		case ADD:
			result = cfg_add(msg_addr, list_num);//增加，目前与修改同
			break;
		case DELETE:
			result = cfg_delete(msg_addr, list_num);//删除该DeviceID中的配置
			break;
		case CHANGE:
			result = cfg_change(msg_addr, list_num);//修改
			break;
		
		default:
			socket_syslog_write_hex((char*)&op_type, sizeof(op_type), 0, "op_type error");
			break;
	}
	return result;
}
unsigned char rcv_key(char *msg_addr, int msg_len)
{
	unsigned short	list_num;
	unsigned char	deviceID_len;
	unsigned char	result = 1;

	memcpy(&list_num, msg_addr + pLISTNUM, sizeof(list_num));
	if (list_num > 3 || msg_len < (16 + sizeof(struct key_list0) * list_num))
	{
		socket_syslog_write("list_num error\n");
		return 1;
	}
	memcpy(&deviceID_len, msg_addr + pDIDLEN, sizeof(deviceID_len));
	if (deviceID_len != DIDLen) //目前限定为DIDLen长度的DeviceID，8位
	{
		socket_syslog_write("deviceID_len error\n");
		return 1;
	}
	result = key_update(msg_addr, list_num);
	return result;
	
}
unsigned char rcv_reply(char *msg_addr, int msg_len)
{
	unsigned char	result = 1;
	unsigned char	status;
	status = *(msg_addr + 4);
	if(status)//1 失败了重发
	{
		result = send_msg(&last_msg, last_len);
	}
	else//0 成功了不管
	{
		result = 0;
	}
	
	return result;
}
int send_reply_msg(struct msg_hd0 reply_msg_hd, unsigned char status)
{
	struct reply_msg0 reply_msg = {0};
	if (reply_msg_hd.msg_type == 0x01)
	{
		printf("rcv cfg from user!\n");
		reply_msg.msg_hd.msg_type = 0x10;
	}
	else if (reply_msg_hd.msg_type == 0x03)
	{
		printf("rcv key from user!\n");
		reply_msg.msg_hd.msg_type = 0x30;
	}
	else
		printf("reply_msg.msg_hd.msg_type not right!\n");
	memcpy(&reply_msg.msg_hd.rq_id, &req_id, 2);

	reply_msg.msg_hd.version = reply_msg_hd.version;
	reply_msg.status = status; //0 成功，其他表示失败
	return send_msg(&reply_msg, sizeof(reply_msg));
}


/*处理从密钥云接收到的数据*/
int rcv_msg(char *msg_addr, int msg_len)
{
	socket_syslog_write_hex(msg_addr, msg_len, 0, "rcv msg from server");
	if (msg_len < 16 && msg_len != 8)
	{
		socket_syslog_write("msg_len error\n");
		return 1;
	}
	
	char msg_type;
	unsigned char flag = 1; //失败返回1，成功返回0
	struct msg_hd0 msg_hd = {0};
	
	memcpy(&msg_hd, msg_addr, sizeof(struct msg_hd0));
	msg_type = *(msg_addr + 1);
	
	switch (msg_type)
	{
	case RCV_CFG_MSG:
		flag = rcv_cfg(msg_addr, msg_len);
		break;
	case RCV_KEY_MSG:
		flag = rcv_key(msg_addr, msg_len);
		break;
	case REPLY_RPT_MSG:
		flag = rcv_reply(msg_addr, msg_len);
		break;

	default:
		socket_syslog_write_hex(&msg_type, sizeof(msg_type), 0, "msg_type not support yet!");
		break;
	}
	//如果处理失败或者规则不匹配则回复失败
	if(msg_type != REPLY_RPT_MSG)
		send_reply_msg(msg_hd, flag);//flag 0 成功，其他表示失败
	return 0;
}
/*****************************IP2ID*******************************************************/
//hD			报文头数据
//in_out		0 接收的报文，需解密          1 发出的报文，需加密
//enc_header	加密头的指针
//key			加密密钥的指针
//pkt_len		此报文的长度
//key_len		返回值 0 无需操作 其他 加密密钥长度
int apply_config(struct ip_struct *ip_data, int in_out, struct encHeader *enc_header, char *key, int pkt_len)
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

