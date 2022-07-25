#pragma once
#include"dnsrelay.h"

SOCKET socketLocalServer;//��������socket
SOCKET socketExternalServer;//�������socket
struct sockaddr_in externalAddr, localAddr;//�ⲿ�����ط�������ַ
struct sockaddr_in client, external;//���յı���Դ��ַ
int length_client = sizeof(client);//�ͻ����ĳ���

bool initSocket()
{
	/*���������*/
	WORD wdVersion = MAKEWORD(2, 2);
	WSADATA wdSockMsg;
	int nRes = WSAStartup(wdVersion, &wdSockMsg);

	if (0 != nRes)
	{
		switch (nRes)
		{
		case WSASYSNOTREADY://ϵͳ�������⣬�������ԣ����ws2_32���Ƿ����
			printf("�������ԣ����߼�������\n"); break;
		case WSAVERNOTSUPPORTED://�汾�ⲻ֧��
			printf("����������\n"); break;
		case WSAEINPROGRESS://�����ڼ��������
			printf("����������\n"); break;
		case WSAEPROCLIM://Windows Socket������Ӧ�ó�������
			printf("��ص�һЩ����Ҫ�����\n"); break;
		}
		return false;
	}

	if (2 != HIBYTE(wdSockMsg.wVersion) || 2 != LOBYTE(wdSockMsg.wVersion))
	{
		//�汾���ԣ��ر������
		WSACleanup();
		return false;
	}

	/*����������socket*/
	socketLocalServer = socket(AF_INET, SOCK_DGRAM, 0);
	socketExternalServer = socket(AF_INET, SOCK_DGRAM, 0);
	//���������ֱ�Ϊ��ַ������(IPv4)���׽������͡�Э������(UDP)
	if (INVALID_SOCKET == socketLocalServer || INVALID_SOCKET == socketExternalServer)//��������
	{
		int a = WSAGetLastError();
		//���������
		WSACleanup();
		return false;
	}

	/*��socket����Ϊ������ģʽ*/
	int non_block = 1;
	ioctlsocket(socketLocalServer, FIONBIO, (u_long FAR*)&non_block);
	ioctlsocket(socketExternalServer, FIONBIO, (u_long FAR*)&non_block);

	/*�󶨵�ַ���˿�*/
	externalAddr.sin_family = AF_INET;
	externalAddr.sin_addr.s_addr = inet_addr(DNSstring);
	externalAddr.sin_port = htons(53);//dns�˿�Ϊ53

	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = INADDR_ANY;
	localAddr.sin_port = htons(53);//dns�˿�Ϊ53

	/*�����ظ�����*/
	int reuse = 1;
	setsockopt(socketLocalServer, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	/*�󶨱���socket�ĵ�ַ*/
	if (SOCKET_ERROR == bind(socketLocalServer, (const struct sockaddr *)&localAddr, sizeof(localAddr)))
	{
		printf("Bind socket port failed.\n");
		int a = WSAGetLastError();
		closesocket(socketLocalServer);
		WSACleanup();
		return false;
	}

	printf("Bind socket port successfully.\n");

	return true;
}

void Output_Packet(char *buf, int length)
{
	unsigned char unit;
	printf("Packet length = %d\n", length);
	printf("Details of the package:\n");
	for (int i = 0; i < length; i++)
	{
		unit = (unsigned char)buf[i];
		printf("%02x ", unit);
	}
	printf("\n");
}

void recvExtern()
{
	char buf[MAX_BUF_SIZE];
	memset(buf, 0, MAX_BUF_SIZE);
	int length = -1;
	length = recvfrom(socketExternalServer, buf, sizeof(buf), 0, (struct sockaddr*)&external, &length_client); 

	if (length > -1)
	{
		if (debugLevel >= 1)
		{
			printf("\n\n---- Recv : Extern [IP:%s]----\n", inet_ntoa(external.sin_addr));
			if(debugLevel==2)
			Output_Packet(buf, length);//�����������
		}
	}

	/*�˴����ý����ⲿ���������ĵĺ���*/
	anaDNSBuf(buf,length);
}

void recvLocal()
{
	char buf[MAX_BUF_SIZE];
	memset(buf, 0, MAX_BUF_SIZE);
	int length = -1;
	length = recvfrom(socketLocalServer, buf, sizeof(buf), 0, (struct sockaddr*)&client, &length_client);

	if (length > -1)
	{
		/*����Ipv6�����д���*/
		/*if (buf[length - 3] == 28)
		{
			return;
		}*/
			
		if (debugLevel >= 1)
		{
			printf("\n\n---- Recv : Client [IP:%s]----\n", inet_ntoa(client.sin_addr));
			if(debugLevel==2)
			Output_Packet(buf, length);//�����������
		}

		/*�˴����ý����ͻ����ĵĺ���*/
		anaClientBuf(buf,length);
	}
}