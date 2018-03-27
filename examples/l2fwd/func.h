#ifndef __FUNC_H__
#define __FUNC_H__

void printHex(char *data, int data_len, int padding_len, char *pt_mark);
unsigned long read_uc_dat(unsigned char **p_conf, unsigned char number);
int socket_syslog_write(char *strto);
int socket_syslog_write_hex(char *data, int data_len, int padding_len, char *strto);
int readline(int fd, char *vptr, size_t maxlen);
int pkt_filter(struct rte_mbuf *m);

#endif