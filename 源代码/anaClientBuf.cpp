#include"dnsrelay.h"

/*���ID�Ƿ���ʧЧ*/
int Check_ID_Expired(IDtransTable* record)
{
		return record->expire_time > 0 && time(NULL) > record->expire_time;
}

/* ��ĳ����Դ��¼������Чʱ�� */
void Set_ID_Expire(IDtransTable* record, int ttl)
{
	record->expire_time = time(NULL) + ttl;   /* expire_time = ����ʱ�� + ttl */
}

unsigned short Register_New_ID(unsigned short ID, SOCKADDR_IN temp, BOOL if_done)
{
	int i = 0;
	for (i = 0; i != MAX_ID_TABLE_SIZE; ++i)
	{
		/*�ҵ���ʧЧ����������ϵ�ID*/
		if (Check_ID_Expired(&idTable[i]) == 0 || idTable[i].done == TRUE)
		{
			idTable[i].old_ID = ID;     /* ID */
			idTable[i].client = temp;   /* socket_addr */
			idTable[i].done = if_done;  /* ��¼�Ƿ��Ѵ������ */
			Set_ID_Expire(&idTable[i], ID_EXPIRE_TIME);
			idCount++;
			if (debugLevel)
			{
				printf("New ID : %d registered successfully\n", i + 1);
				printf("#ID Count : %d\n", idCount);
			}
			break;
		}
	}
	if (i == MAX_ID_TABLE_SIZE) /* ע��ʧ�� */
		return 0;
	return (unsigned short)i + 1; /* ������ID */
}

void anaClientBuf(char *buf,int length)
{
	char url[65];
	int output_cache_flag = 0;

	if (length > 0)
	{
		char ori_url[65];
		memcpy(ori_url, &(buf[DNS_HEAD_SIZE]), length); /*��ȡ��ԭʼ��url */
		Convert_to_Url(ori_url, url); /*��ԭʼ��urlת��������*/

		char ip[16];
		int ipv6_flag = 0;
		domainIp *local_p = ipList->nextptr;
		domainIp *cache_p = cache->nextptr;
		domainIp *cache_last = cache;

		if (buf[length - 3] != 28)
		{
			while (local_p != NULL && strcmp(local_p->domainName, url) != 0) local_p = local_p->nextptr;
			while (cache_p != NULL && strcmp(cache_p->domainName, url) != 0)
			{
				cache_last = cache_p;
				cache_p = cache_p->nextptr;
			}
		}
		else ipv6_flag = 1;

			if ((local_p == NULL && cache_p == NULL)||ipv6_flag==1)/*����ѯ���������ڱ��ػ�cache��*/
			{
				unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
				memcpy(pID, buf, sizeof(unsigned short)); /* ��¼ID */
				unsigned short nID = Register_New_ID(*pID, client, FALSE); /* ��IDת������ע���µ�ID */
				if (nID == 0)
				{
					if (debugLevel >= 1)
						printf("Register failed, the ID transfer table is full.\n");
				}
				else
				{
					memcpy(buf, &nID, sizeof(unsigned short));
					length = sendto(socketExternalServer, buf, length, 0, (struct sockaddr*)&externalAddr, sizeof(externalAddr));/* �������͸��ⲿDNS */
					if (debugLevel >= 1)
					{
						printf("\nSend to external DNS server [Url : %s]\n", url);
						if (debugLevel == 2)
							Output_Packet(buf, length);
					}
				}
				free(pID);
			}

			else/*�����ڱ��ػ�cache��*/
			{
				if (local_p != NULL) /* �ڱ���txt�ļ��� */
				{
					strcpy(ip, local_p->ip); /* �ӱ��������л�ȡIP*/
					if (debugLevel >= 1)
						printf("Read from local data [Url:%s -> IP:%s]\n", url, ip);
				}
				else /* ��cache�� */
				{
					strcpy(ip, cache_p->ip); /* ��cache�л�ȡip */

					/*������Դ��¼�ƶ���cacheͷ��*/
					cache_last->nextptr = cache_p->nextptr;
					cache_p->nextptr = cache->nextptr;
					cache->nextptr = cache_p;

					if (debugLevel >= 1)
					{
						printf("Read from cache [Url:%s -> IP:%s]\n", url, ip);
						output_cache_flag = 1;
					}
				}
				char sendbuf[MAX_BUF_SIZE];
				memcpy(sendbuf, buf, length); /*��������� */
				unsigned short a = htons(0x8180);/*��0x8180�������ֽ�˳���������ֽ�˳�� */
				memcpy(&sendbuf[2], &a, sizeof(unsigned short)); /*��ͷ����־λ*/

				if (strcmp(ip, "0.0.0.0") == 0)    /* �ж��Ƿ�Ӧ������ */
				{
					unsigned short a = htons(0x8183);/*��0x8180�������ֽ�˳���������ֽ�˳�� */
					memcpy(&sendbuf[2], &a, sizeof(unsigned short)); /*��ͷ����־λ*/
				}
				else a = htons(0x0001);	/* answerλ��1 */
				memcpy(&sendbuf[6], &a, sizeof(unsigned short));

				int curLen = 0;
				char answer[16];
				unsigned short Name = htons(0xc00c);  /* ����ָ�� */
				memcpy(answer, &Name, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned short TypeA = htons(0x0001);  /* Type */
				memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned short ClassA = htons(0x0001);  /* Class */
				memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned long timeLive = htonl(0x7b); /* Time to live */
				memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
				curLen += sizeof(unsigned long);

				unsigned short IPLen = htons(0x0004);  /* Data length */
				memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
				curLen += sizeof(unsigned short);

				unsigned long IP = (unsigned long)inet_addr(ip); /* IP */
				memcpy(answer + curLen, &IP, sizeof(unsigned long));
				curLen += sizeof(unsigned long);
				curLen += length;
				memcpy(sendbuf + length, answer, sizeof(answer));

				length = sendto(socketLocalServer, sendbuf, curLen, 0, (SOCKADDR*)&client, sizeof(client)); /* ��������client*/

				if (length < 0)
					printf("Error : Send packet -> length < 0\n");

				char *p;
				p = sendbuf + length - 4;
				if (debugLevel >= 1)
				{
					printf("\nSend packet [Url:%s -> IP:%u.%u.%u.%u]\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
					if (debugLevel == 2)
						Output_Packet(sendbuf, length);
				}
				if (output_cache_flag && debugLevel >= 1)
					output_cache();
			}
	}
}