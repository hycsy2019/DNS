#pragma once

#ifndef DNS_RELAY_H
#define DNS_RELAY_H

#include<stdio.h>
#include<string.h>
#include<WinSock2.h>
#include<time.h>
#pragma comment(lib,"ws2_32.lib")

#define DEFAULTDNS "10.3.9.5"//默认外部DNS地址
#define DEFAULTFILE "dnsrelay.txt"//默认读取文件
#define MAX_BUF_SIZE 1500//收包发包大小
#define MAX_ID_TABLE_SIZE 16//ID转换表大小
#define DNS_HEAD_SIZE 12//DNS报文头部长
#define ID_EXPIRE_TIME 10//ID的有效时间为10s
#define MAX_CACHE_SIZE 5//cache最大记录数

typedef struct domainip
{
	char domainName[200] = {'\0'};//域名
	char ip[16] = {'\0'};//ip地址
	struct domainip *nextptr = NULL;//下一节点
}domainIp;

typedef struct
{
	unsigned short old_ID; //旧的ID
	BOOL done;    //标志响应是否已处理完毕
	SOCKADDR_IN client;   //客户端地址
	int expire_time;   //失效时间
}IDtransTable;

extern SOCKET socketLocalServer;//本服务器socket
extern SOCKET socketExternalServer;//外服务器socket
extern struct sockaddr_in externalAddr, localAddr;//外部、本地服务器地址
extern struct sockaddr_in client, external;//接收的报文源地址
extern int debugLevel;//调试信息级别
extern char fileName[50];//配置文件名
extern char DNSstring[16];//读取的或默认的外部DNS地址
extern domainIp *ipList ;//每个元素包含相对应的域名和ip地址的链表
extern domainip *cache;//由外部DNS应答形成的缓存链表
extern IDtransTable idTable[MAX_ID_TABLE_SIZE];//ID转换表
extern int idCount;//有效id数量

extern bool initSocket();//初始化、绑定socket
extern void recvExtern();//接收来自外部服务器的报文
extern void recvLocal();//接收来自本服务器及客户的报文
extern void Convert_to_Url(char* buf, char* dest);//包数据转换为域名
extern void output_cache();//打印cache里的内容
extern void Output_Packet(char *buf, int length);//打印数据包

void anaClientBuf(char *buf,int length);//分析用户报文
void anaDNSBuf(char *buf, int length);//分析外部服务器报文

#endif