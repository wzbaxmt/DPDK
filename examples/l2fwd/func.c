//data 
//data_len + padding_len
//pt_mark 
void printkHex(char *data, int data_len, int padding_len, char* pt_mark)
{	
	int i = 0;
	printf("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len+padding_len); i ++) 
	{
		if(0 == (i%16) && i != 0)
			printf("[%d]\n",i/16);
		printf("%02x ", data[i] & 0xFF);
	}
	printf("\n");
}

