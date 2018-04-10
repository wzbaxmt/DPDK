#ifndef __FUNC_H__
#define __FUNC_H__
const int MAX_LINE = 1024;
const int PORT = 6000;
const int BACKLOG = 10;
const int LISTENQ = 6666; //unused
const int MAX_CONNECT = 20;

int init_connect(void);
int connect_to_server(void);
int destory_connect(void);

#endif