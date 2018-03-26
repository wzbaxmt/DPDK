#ifndef __FUNC_H__
#define __FUNC_H__
void printkHex(char *data, int data_len, int padding_len, char* pt_mark);



int pkt_filter(struct rte_mbuf *m);

#endif