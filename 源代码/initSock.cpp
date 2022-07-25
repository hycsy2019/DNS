#pragma once
#include"dnsrelay.h"

SOCKET socketLocalServer;//本服务器socket
SOCKET socketExternalServer;//外服务器socket
struct sockaddr_in externalAddr, localAddr;//外部、本地服务器地址
struct sockaddr_in client, external;//接收的报文源地址
int length_client = sizeof(client);//客户报文长度

bool initSocket()
{
	/*配置网络库*/
	WORD wdVersion = MAKEWORD(2, 2);
	WSADATA wdSockMsg;
	int nRes = WSAStartup(wdVersion, &wdSockMsg);

	if (0 != nRes)
	{
		switch (nRes)
		{
		case WSASYSNOTREADY://系统配置问题，重启电脑，检查ws2_32库是否存在
			printf("重启电脑，或者检查网络库\n"); break;
		case WSAVERNOTSUPPORTED://版本库不支持
			printf("请更新网络库\n"); break;
		case WSAEINPROGRESS://运行期间出现阻塞
			printf("请重新启动\n"); break;
		case WSAEPROCLIM://Windows Socket限制了应用程序数量
			printf("请关掉一些不必要的软件\n"); break;
		}
		return false;
	}

	if (2 != HIBYTE(wdSockMsg.wVersion) || 2 != LOBYTE(wdSockMsg.wVersion))
	{
		//版本不对，关闭网络库
		WSACleanup();
		return false;
	}

	/*创建服务器socket*/
	socketLocalServer = socket(AF_INET, SOCK_DGRAM, 0);
	socketExternalServer = socket(AF_INET, SOCK_DGRAM, 0);
	//三个参数分别为地址的类型(IPv4)、套接字类型、协议类型(UDP)
	if (INVALID_SOCKET == socketLocalServer || INVALID_SOCKET == socketExternalServer)//创建出错
	{
		int a = WSAGetLastError();
		//清理网络库
		WSACleanup();
		return false;
	}

	/*将socket设置为非阻塞模式*/
	int non_block = 1;
	ioctlsocket(socketLocalServer, FIONBIO, (u_long FAR*)&non_block);
	ioctlsocket(socketExternalServer, FIONBIO, (u_long FAR*)&non_block);

	/*绑定地址及端口*/
	externalAddr.sin_family = AF_INET;
	externalAddr.sin_addr.s_addr = inet_addr(DNSstring);
	externalAddr.sin_port = htons(53);//dns端口为53

	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = INADDR_ANY;
	localAddr.sin_port = htons(53);//dns端口为53

	/*允许重复捆绑*/
	int reuse = 1;
	setsockopt(socketLocalServer, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	/*绑定本地socket的地址*/
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
			Output_Packet(buf, length);//输出包的内容
		}
	}

	/*此处调用解析外部服务器报文的函数*/
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
		/*不对Ipv6包进行处理*/
		/*if (buf[length - 3] == 28)
		{
			return;
		}*/
			
		if (debugLevel >= 1)
		{
			printf("\n\n---- Recv : Client [IP:%s]----\n", inet_ntoa(client.sin_addr));
			if(debugLevel==2)
			Output_Packet(buf, length);//输出包的内容
		}

		/*此处调用解析客户报文的函数*/
		anaClientBuf(buf,length);
	}
}