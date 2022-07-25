#include"dnsrelay.h"

IDtransTable idTable[MAX_ID_TABLE_SIZE];//ID转换表
int idCount ;//有效ID数量
domainip *cache;//缓存的域名和ip链表
int cacheSize;//cache当前大小

void Convert_to_Url(char* buf, char* dest)
{
	int i = 0, j = 0, k = 0, len = strlen(buf);
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//域名未结束 
		{
			for (j = buf[i], i++; j > 0; j--, i++, k++)//复制域名
				dest[k] = buf[i];
		}
		if (buf[i] != 0) //若该等级域名结束且整个域名未读取完，加上.
		{
			dest[k] = '.';
			k++;
		}
	}
	dest[k] = '\0';
}

/*打印cache内容*/
void output_cache()
{
	printf("\n\n--------------  Cache  --------------\n");
	int j = 0;
	for (domainip *cur_p=cache->nextptr;cur_p!=NULL;cur_p=cur_p->nextptr)
	{
		printf("#%d Url:%s -> IP:%s\n", j++, cur_p->domainName, cur_p->ip);
	}
}

/*将新的资源记录加入cache*/
void Add_Record_to_Cache(char *url, char *ip)
{
	domainIp *cur_p = cache->nextptr;
	domainIp *last_p = cache;
	domainIp *last_last_p = NULL;
	while (cur_p != NULL && strcmp(cache->domainName, url) != 0)
	{
		last_last_p = last_p;
		last_p = cur_p;
		cur_p = cur_p->nextptr;
	}

	if (cur_p!=NULL) /*cache中已有该资源记录*/
	{
		strcpy(cur_p->ip,ip); /* 更新ip */

		/*将该资源记录移动至cache头部*/
		last_p->nextptr = cur_p->nextptr;
		cur_p->nextptr = cache->nextptr;
		cache->nextptr = cur_p;
	}

	else /* 该资源记录不在cache中 */
	{
		/*如果cache已满，删除最近最少使用记录*/
		if (cacheSize == MAX_CACHE_SIZE)
		{
			last_last_p->nextptr = NULL;
			cacheSize--;
		}

		/* 加入新记录*/
		domainIp *head = new domainIp;
		head->nextptr = cache;
		strcpy(cache->domainName, url);
		strcpy(cache->ip, ip);
		cache = head;
		if(debugLevel>=1)
		output_cache();
		cacheSize++;
	}
}

void anaDNSBuf(char *buf,int length)
{
	char url[65];

	if (length > -1)
	{
		/* 得到报文ID */
		unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
		memcpy(pID, buf, sizeof(unsigned short));
		int id_index = (*pID) - 1;
		free(pID);

		/*转换*/
		memcpy(buf, &idTable[id_index].old_ID, sizeof(unsigned short));
		idCount--;
		if (debugLevel >= 1)
			printf("#ID Count : %d\n", idCount);
		idTable[id_index].done = TRUE;

		client = idTable[id_index].client;

		int nquery = ntohs(*((unsigned short*)(buf + 4))), nresponse = ntohs(*((unsigned short*)(buf + 6)));
		char* p = buf + 12; //p指向Question区域
		char ip[16];
		int ip1, ip2, ip3, ip4;

		for (int i = 0; i < nquery; i++)
		{
			Convert_to_Url(p, url);
			while (*p > 0)
				p += (*p) + 1;
			p += 5; //指向下一个query
		}

		if (nresponse > 0 && debugLevel >= 1)
			printf("Receive from extern [Url : %s]\n", url);

		for (int i = 0; i < nresponse; ++i)
		{
			if ((unsigned char)*p == 0xc0) //如果域名区域是个偏移指针
				p += 2;
			else //如果域名区域为域名
			{
				while (*p > 0)
					p += (*p) + 1;
				++p;
			}

			unsigned short resp_type = ntohs(*(unsigned short*)p);  /* Type */
			p += 2;
			unsigned short resp_class = ntohs(*(unsigned short*)p); /* Class */
			p += 2;
			unsigned short high = ntohs(*(unsigned short*)p); /* TTL high bit */
			p += 2;
			unsigned short low = ntohs(*(unsigned short*)p);  /* TTL low bit */
			p += 2;
			int ttl = (((int)high) << 16) | low;    /* TTL combinate */
			int datalen = ntohs(*(unsigned short*)p);  /* Data length */
			p += 2;
			if (debugLevel >= 2)
				printf("Type -> %d,  Class -> %d,  TTL -> %d\n", resp_type, resp_class, ttl);

			if (resp_type == 1) /* Type A */
			{
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;

				sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debugLevel)
					printf("IP address : %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);

				/*将资源记录加入cache*/
				Add_Record_to_Cache(url, ip);
				break;
			}
			else p += datalen;  /* 如果应答包非Type A,忽略*/
		}

		/* 将包发送给客户 */
		int length1 = -1;
		length1 = sendto(socketLocalServer, buf, length, 0, (SOCKADDR*)&client, sizeof(client));

		char *p1;
		p1 = buf + length - 4;
		if (debugLevel >= 1)
		{
			printf("\nSend packet [Url:%s -> IP:%u.%u.%u.%u]\n", url, (unsigned char)*p1, (unsigned char)*(p1 + 1), (unsigned char)*(p1 + 2), (unsigned char)*(p1 + 3));
			if (debugLevel == 2)
				Output_Packet(buf, length);
		}
	}
}

