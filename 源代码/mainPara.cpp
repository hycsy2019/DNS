#include"dnsrelay.h"

int debugLevel;//调试信息级别
char fileName[50];//配置文件名
char DNSstring[16];//读取的或默认的外部DNS地址
domainIp *ipList = NULL;//每个元素包含相对应的域名和ip地址的链表

void readPara(int argc, char *argv[])
{
	if (argc > 1 && argv[1][0] == '-')
	{
		/*根据读入的参数确定调试等级*/
		if (argv[1][1] == 'd') debugLevel++;
		if (argv[1][2] == 'd') debugLevel++;
	}
	printf("Debug level: %d\n", debugLevel);

	/*如果参数包含外部DNS地址则读入，否则使用默认DNS*/
	if (argc > 2)
	{
		strcpy_s(DNSstring, argv[2]);
		printf("Name Server: %s\n", argv[2]);
	}
	else
	{
		strcpy_s(DNSstring, DEFAULTDNS);
		printf("Name Server: %s by default\n", DEFAULTDNS);
	}

	/*如果参数包含配置文件名称则读入，否则使用默认配置文件*/
	if (argc > 3)
	{
		strcpy_s(fileName, argv[3]);
		printf("Configuration file: %s\n", argv[3]);
	}
	else
	{
		strcpy_s(fileName, DEFAULTFILE);
		printf("Configuration file: %s by default\n", DEFAULTFILE);
	}
}
	
bool readFile()
{
	FILE *file;

	/*差错处理，无法打开配置文件*/
	int error;
	if ((error = fopen_s(&file, fileName, "r")) != 0)
	{
		printf("Fail to open %s\n", fileName);
		return false;
	}

	/*构造ip域名链表*/
	char url[200], ip[16];
	int i = 1;
	ipList = new domainIp;
	while (fscanf_s(file, "%s %s", ip, 16, url, 200) > 0)
	{
		domainIp *head = new domainIp;
		head->nextptr = ipList;
		strcpy_s(ipList->domainName, url);
		strcpy_s(ipList->ip, ip);
		if (debugLevel > 1)
			printf("%d: %s\t%s\n", i, ip, url);
		i++;
		ipList = head;
	}

	/*关闭文件*/
	fclose(file);
	return true;
}

int main(int argc, char*argv[])
{
	/*输出程序信息*/
	printf("DNSRELAY,Build: Aug 17 2020\n");
	printf("Usage: dnsrelay [-d|-dd] [<dns-server>] [<db-file>]\n");

	/*初始化*/
	cache = new domainIp;

	/*读取参数*/
	readPara(argc, argv);

	/*读取配置文件*/
	if (!readFile()) return -1;

	/*初始化socket*/
	if (!initSocket()) return -1;
	
	//debugLevel = 2;

	while (true)
	{
		recvExtern();//处理外部服务器发来的报文
		recvLocal();//处理客户端发来的报文
	}
}