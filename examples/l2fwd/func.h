#ifndef __FUNC_H__
#define __FUNC_H__
struct encHeader //26 ? 加密头
{
	unsigned char flag;
	unsigned short msglen;
	unsigned char encType; //0x01 aes(cbc) 0x10 sm4(ecb)
	unsigned char identification[2];
	unsigned char flags[2];
	unsigned char keyID[16];
	__sum16 CRC;
};

struct psd_header //6 用于计算校验和
{
	unsigned int saddr;
	unsigned int daddr;
	char mbz;
	char ptcl;
	unsigned short tcpl;
};

struct msg_hd0 //4 与上层交互请求头
{
	unsigned char version;  //版本号，默认为1
	unsigned char msg_type; //0x01配置下发,0x10配置下发确认; 0x02配置上报,0x20,配置上报确认; 0x03密钥下发,0x30密钥下发确认
	unsigned short rq_id;   //消息序号，由发送端决定
};

struct key_list0 //52 与上层交互密钥结构体
{
	unsigned char key_id[16];
	unsigned char key_len;
	unsigned char reserved[3];
	unsigned char key_value[32];
};

struct config_list0 //32 与上层交互配置结构
{
	unsigned char rule_id[4]; //规则编号，数据上报时，无本字段//4个字节的数据
	unsigned char enc_type;   //加密类型；0-不加密，1-aes
	unsigned short pro_type;  //协议类型；6-tcp，17-udp
	unsigned char reserved;
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char sPort[2];
	unsigned char dPort[2];
};

struct reply_msg0 //8 回复信息
{
	struct msg_hd0 msg_hd;	 //4
	unsigned char status;	  //1 0x00 success
	unsigned char reserved[3]; //3
};

struct rcv_node //保存目标设备的配置、DeviceID、KeyID、Key
{
	unsigned short config_num;
	unsigned short key_num;
	unsigned char DeviceID[16]; //8    DeviceID包含在KeyID中
	unsigned char DeviceID_len; //
	void *config_list;
	struct key_list0 key_list[3]; //0 当前使用，优先存放在0
	struct list_head store_list;
};

struct IP2ID //接受报文后自身存储IP与DeviceID对应关系的链表,用来上报给上层应用
{
	unsigned char sPort[2];
	unsigned char dPort[2];
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char DeviceID[DIDLen];
	int report;				 //IP与DeviceID关系上报开关，0 未上报，1已上报
	unsigned int DataIn;	 //自上次上报后流入服务器的加密字节数 Max 4.3GB
	unsigned int DataOut;	//自上次上报后流出服务器的加密字节数 Max 4.3GB
	unsigned short reportID; //上报序号,Max 65535
	struct list_head store_list;
};

struct CFG_MSG //与上层交互配置
{
	struct msg_hd0 msg_hd;			 //4
	unsigned char op_type;			 //1 操作类型：0为清空，1为全量替换，2为增加，3为删除，4为修改。
	unsigned char deviceID_len;		 //1 设备ID长度
	unsigned short list_num;		 //2 配置个数
	unsigned char deviceID[DIDLen];  //8 长度由Device ID Len决定，设备ID
	struct config_list0 config_list; //长度为List Number*32配置列表
};

struct FLOW_MSG //与上层交互配置
{
	struct msg_hd0 msg_hd;			//4
	unsigned char op_type;			//1 操作类型：0为清空，1为全量替换，2为增加，3为删除，4为修改。
	unsigned short list_num;		//2 配置个数
	unsigned char deviceID_len;		//1 设备ID长度
	unsigned char deviceID[DIDLen]; //8 长度由Device ID Len决定，设备ID
	unsigned int data_in;			//流入数据字节数
	unsigned int data_out;			//流出数据字节数
};
void printHex(char *data, int data_len, int padding_len, char *pt_mark);
unsigned long read_uc_dat(unsigned char **p_conf, unsigned char number);
int socket_syslog_write(char *strto);
int socket_syslog_write_hex(char *data, int data_len, int padding_len, char *strto);
int readline(int fd, char *vptr, size_t maxlen);
int pkt_filter(struct rte_mbuf *m);

#endif