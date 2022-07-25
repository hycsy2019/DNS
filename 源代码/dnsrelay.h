#pragma once

#ifndef DNS_RELAY_H
#define DNS_RELAY_H

#include<stdio.h>
#include<string.h>
#include<WinSock2.h>
#include<time.h>
#pragma comment(lib,"ws2_32.lib")

#define DEFAULTDNS "10.3.9.5"//Ĭ���ⲿDNS��ַ
#define DEFAULTFILE "dnsrelay.txt"//Ĭ�϶�ȡ�ļ�
#define MAX_BUF_SIZE 1500//�հ�������С
#define MAX_ID_TABLE_SIZE 16//IDת�����С
#define DNS_HEAD_SIZE 12//DNS����ͷ����
#define ID_EXPIRE_TIME 10//ID����Чʱ��Ϊ10s
#define MAX_CACHE_SIZE 5//cache����¼��

typedef struct domainip
{
	char domainName[200] = {'\0'};//����
	char ip[16] = {'\0'};//ip��ַ
	struct domainip *nextptr = NULL;//��һ�ڵ�
}domainIp;

typedef struct
{
	unsigned short old_ID; //�ɵ�ID
	BOOL done;    //��־��Ӧ�Ƿ��Ѵ������
	SOCKADDR_IN client;   //�ͻ��˵�ַ
	int expire_time;   //ʧЧʱ��
}IDtransTable;

extern SOCKET socketLocalServer;//��������socket
extern SOCKET socketExternalServer;//�������socket
extern struct sockaddr_in externalAddr, localAddr;//�ⲿ�����ط�������ַ
extern struct sockaddr_in client, external;//���յı���Դ��ַ
extern int debugLevel;//������Ϣ����
extern char fileName[50];//�����ļ���
extern char DNSstring[16];//��ȡ�Ļ�Ĭ�ϵ��ⲿDNS��ַ
extern domainIp *ipList ;//ÿ��Ԫ�ذ������Ӧ��������ip��ַ������
extern domainip *cache;//���ⲿDNSӦ���γɵĻ�������
extern IDtransTable idTable[MAX_ID_TABLE_SIZE];//IDת����
extern int idCount;//��Чid����

extern bool initSocket();//��ʼ������socket
extern void recvExtern();//���������ⲿ�������ı���
extern void recvLocal();//�������Ա����������ͻ��ı���
extern void Convert_to_Url(char* buf, char* dest);//������ת��Ϊ����
extern void output_cache();//��ӡcache�������
extern void Output_Packet(char *buf, int length);//��ӡ���ݰ�

void anaClientBuf(char *buf,int length);//�����û�����
void anaDNSBuf(char *buf, int length);//�����ⲿ����������

#endif