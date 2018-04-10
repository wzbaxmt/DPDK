#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "client.h"

//初始化服务器连接
//返回：成功0 失败1
int init_connect()
{
	struct sockaddr_in servaddr;
	char *srv_ip;
	int pid;
	srv_ip = "127.0.0.1";
	pid = getpid();
	printf("parent pid is %d\n",pid);
	/*(1) 创建套接字*/
	if((sockfd = socket(AF_INET , SOCK_STREAM , 0)) == -1)
	{
		perror("socket error");
		return 1;
	}

	/*(2) 设置链接服务器地址结构*/
	bzero(&servaddr , sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	if(inet_pton(AF_INET , srv_ip , &servaddr.sin_addr) < 0)
	{
		printf("inet_pton error for %s\n",srv_ip);
		return 1;
	}

	/*(3) 发送链接服务器请求*/
	if( connect(sockfd , (struct sockaddr *)&servaddr , sizeof(servaddr)) < 0)
	{
		perror("connect error");
		return 1;
	}
	
	return 0;
}

//读取一次服务器发来的数据
//返回：成功0 失败1
int connect_to_server()
{
	/*(4) 消息处理*/
	char sendline[MAX_LINE] , recvline[MAX_LINE];
	bzero(&sendline , MAX_LINE);
	bzero(&recvline , MAX_LINE);
	while(1)//最后会有/n	
	{
		int rcv_byte;
		rcv_byte = readline(sockfd , recvline , MAX_LINE);
		if(rcv_byte == 0)
		{
			perror("server terminated prematurely");
		}
		rcv_msg(recvline, rcv_byte);
		printf("*****************************************\n");
	}
	return 0;
}

//关闭化服务器连接
//返回：成功0 失败1
int destory_connect()
{
	/*(5) 关闭套接字*/
	close(sockfd);
	return 0;
}


