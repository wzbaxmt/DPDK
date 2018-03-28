/*
 * 为本地DPDK端代码
 * 主要为与业务相关代码
 * 与密钥云交互功能实现
*/
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#define REPLY_MSG_LEN	8
#define CFG_MSG_LEN		8
#define KEY_MSG_LEN		8
/*
* 0x01配置下发,0x10配置下发确认; 
* 0x02配置上报,0x20,配置上报确认; 
* 0x03密钥下发,0x30密钥下发确认
*/
#define RCV_CFG_MSG		0x01
#define RCV_KEY_MSG		0x03
#define REPLY_RPT_MSG	0x20

#define REPLY_CFG_MSG	0x10
#define REPLY_KEY_MSG	0x30
#define SEND_RPT_MSG	0x02

#define	CLEAR		0
#define	REPLACE		1
#define ADD			2
#define	DELETE		3
#define	CHANGE		4


#define DIDLen 8		//最大DeviceID字节数
#define KIDLen 16		//最带KeyID字节数

#define pOPTYPE		4
#define pLISTNUM	5
#define	pDIDLEN		7
#define	pDID		8
#define pLIST		16

#define MaxLen		10240

#define ENC_OUT 1
#define DEC_IN 0


/*声明套接字和链接服务器地址*/
int sockfd;
void* ip2id;
void* id2data;
struct ip_struct
{
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char sPort[2];
	unsigned char dPort[2];
};//24 Byte

struct msg_hd0 //4 与上层交互请求头
{
	unsigned char version;  //版本号，默认为1
	unsigned char msg_type; //0x01配置下发,0x10配置下发确认; 0x02配置上报,0x20,配置上报确认; 0x03密钥下发,0x30密钥下发确认
	unsigned short rq_id;   //消息序号，由发送端决定
};

struct reply_msg0 //8 回复信息
{
	struct msg_hd0 msg_hd;	 //4
	unsigned char status;	  //1 0x00 success
	unsigned char reserved[3]; //3
};

struct config_list0 //32 与上层交互配置结构
{
	unsigned char rule_id[4]; //规则编号，数据上报时，无本字段//4个字节的数据
	unsigned char enc_type;   //加密类型；0-不加密，1-aes
	unsigned short pro_type;  //协议类型；6-tcp，17-udp
	unsigned char reserved;
	struct ip_struct ip_data;
};

struct key_list0 //52 与上层交互密钥结构体
{
	unsigned char key_id[16];
	unsigned char key_len;
	unsigned char reserved[3];
	unsigned char key_value[32];
};

struct id2data_struct //保存目标设备的配置、DeviceID、KeyID、Key
{
	unsigned char DeviceID[DIDLen];
	unsigned short key_num;
	unsigned short config_num;
	struct key_list0 key_list[3]; //0 当前使用，优先存放在0
	void *config_list;//变长，
};

struct ip2id_struct
{
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char sPort[2];
	unsigned char dPort[2];
	unsigned char DeviceID[DIDLen];
	int report;				 //IP与DeviceID关系上报开关，0 未上报，1已上报
	unsigned int DataIn;	 //自上次上报后流入服务器的加密字节数 Max 4.3GB
	unsigned int DataOut;	//自上次上报后流出服务器的加密字节数 Max 4.3GB
	unsigned short reportID; //上报序号,Max 65535	
};

struct encHeader //26 ? 加密头
{
	unsigned char flag;
	unsigned short msglen;
	unsigned char encType; //0x01 aes(cbc) 0x10 sm4(ecb)
	unsigned char identification[2];
	unsigned char flags[2];
	unsigned char keyID[16];
	unsigned short CRC;
};

unsigned char rcv_cfg(char* msg_addr, int msg_len);
unsigned char rcv_key(char* msg_addr, int msg_len);
unsigned char rcv_reply(char* msg_addr, int msg_len);
int rcv_msg(char* msg_addr, int msg_len);
int send_msg(char* msg_addr, int msg_len);

int send_reply_msg(struct msg_hd0 reply_msg_hd, unsigned char status);

int apply_config(struct ip_struct *ip_data, int in_out, struct encHeader *enc_header, char *key, int pkt_len);



#endif

