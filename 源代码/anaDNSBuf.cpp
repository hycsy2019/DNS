#include"dnsrelay.h"

IDtransTable idTable[MAX_ID_TABLE_SIZE];//IDת����
int idCount ;//��ЧID����
domainip *cache;//�����������ip����
int cacheSize;//cache��ǰ��С

void Convert_to_Url(char* buf, char* dest)
{
	int i = 0, j = 0, k = 0, len = strlen(buf);
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)//����δ���� 
		{
			for (j = buf[i], i++; j > 0; j--, i++, k++)//��������
				dest[k] = buf[i];
		}
		if (buf[i] != 0) //���õȼ�������������������δ��ȡ�꣬����.
		{
			dest[k] = '.';
			k++;
		}
	}
	dest[k] = '\0';
}

/*��ӡcache����*/
void output_cache()
{
	printf("\n\n--------------  Cache  --------------\n");
	int j = 0;
	for (domainip *cur_p=cache->nextptr;cur_p!=NULL;cur_p=cur_p->nextptr)
	{
		printf("#%d Url:%s -> IP:%s\n", j++, cur_p->domainName, cur_p->ip);
	}
}

/*���µ���Դ��¼����cache*/
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

	if (cur_p!=NULL) /*cache�����и���Դ��¼*/
	{
		strcpy(cur_p->ip,ip); /* ����ip */

		/*������Դ��¼�ƶ���cacheͷ��*/
		last_p->nextptr = cur_p->nextptr;
		cur_p->nextptr = cache->nextptr;
		cache->nextptr = cur_p;
	}

	else /* ����Դ��¼����cache�� */
	{
		/*���cache������ɾ���������ʹ�ü�¼*/
		if (cacheSize == MAX_CACHE_SIZE)
		{
			last_last_p->nextptr = NULL;
			cacheSize--;
		}

		/* �����¼�¼*/
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
		/* �õ�����ID */
		unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
		memcpy(pID, buf, sizeof(unsigned short));
		int id_index = (*pID) - 1;
		free(pID);

		/*ת��*/
		memcpy(buf, &idTable[id_index].old_ID, sizeof(unsigned short));
		idCount--;
		if (debugLevel >= 1)
			printf("#ID Count : %d\n", idCount);
		idTable[id_index].done = TRUE;

		client = idTable[id_index].client;

		int nquery = ntohs(*((unsigned short*)(buf + 4))), nresponse = ntohs(*((unsigned short*)(buf + 6)));
		char* p = buf + 12; //pָ��Question����
		char ip[16];
		int ip1, ip2, ip3, ip4;

		for (int i = 0; i < nquery; i++)
		{
			Convert_to_Url(p, url);
			while (*p > 0)
				p += (*p) + 1;
			p += 5; //ָ����һ��query
		}

		if (nresponse > 0 && debugLevel >= 1)
			printf("Receive from extern [Url : %s]\n", url);

		for (int i = 0; i < nresponse; ++i)
		{
			if ((unsigned char)*p == 0xc0) //������������Ǹ�ƫ��ָ��
				p += 2;
			else //�����������Ϊ����
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

				/*����Դ��¼����cache*/
				Add_Record_to_Cache(url, ip);
				break;
			}
			else p += datalen;  /* ���Ӧ�����Type A,����*/
		}

		/* �������͸��ͻ� */
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

