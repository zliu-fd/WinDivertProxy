#pragma once

#include <map>
#include <thread>
#include <iostream>
#include <WinSock2.h>
#include <string>

#include "windivert.h"

#pragma comment(lib, "Ws2_32.lib")

#define MAXBUF	0xFFFF

struct EndPoint{
	UINT32 addr;
	USHORT port;

	bool operator<(const EndPoint &ep) const { return (addr < ep.addr || (addr == ep.addr && port < ep.port)); }
	bool operator==(const EndPoint &ep) const { return (addr == ep.addr && port == ep.port); }
	bool operator>(const EndPoint &ep) const { return (addr > ep.addr || (addr == ep.addr && port > ep.port)); }

	EndPoint()	{ }

	EndPoint(UINT32 _addr, USHORT _port)
	{
		addr = _addr;
		port = _port;
	}
};


class TransparentProxy
{
private:
	std::map<EndPoint, EndPoint> ClientToServerMap;
	std::map<EndPoint, UINT32> CurrentSNMap;
	std::map<EndPoint, std::map<UINT32, UINT32>> OutSNMap;
	std::map<EndPoint, std::map<UINT32, UINT32>> InSNMap;
	std::map<EndPoint, std::map<UINT32, UINT32>> InOrignalToActualACKMap;
	bool Monitoring;
	std::thread* MonitorThread;
	HANDLE WinDivertHandle;

	void Request(unsigned char* packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data = NULL, UINT data_len = 0);
	void RequestHTTPS(unsigned char* packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data = NULL, UINT data_len = 0);
	void Response(unsigned char* packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data = NULL, UINT data_len = 0);
	void LogRedirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort, int direction);
	std::string ConvertIP(UINT32 addr);
	// UINT ConstructPacket(unsigned char* buffer, UINT bufferLen, UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort, char* content, UINT contentLen);
	bool StartWith(char* srcStr, char* subStr);

	int debugCount;


public:
	std::string ReadableProxyAddr;
	USHORT ReadableProxyPort;
	UINT32 ProxyAddr;
	USHORT ProxyPort;
	bool Debug;

	TransparentProxy(std::string proxyAddr, USHORT proxyPort);
	~TransparentProxy(void);

	int Start();
	int Stop();

	void Monitor();
};

