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

	bool operator<(const EndPoint &ep) const { return (addr < ep.addr || port < ep.port); }
};


class TransparentProxy
{
private:
	std::map<EndPoint, EndPoint>* ClientToServerMap;
	bool Monitoring;
	std::thread* MonitorThread;
	HANDLE handle;

	void Request(unsigned char *packet);
	void Response(unsigned char *packet);


public:
	UINT32 ProxyAddr;
	USHORT ProxyPort;
	bool Debug;

	TransparentProxy(std::string proxyAddr, USHORT proxyPort);
	~TransparentProxy(void);

	int Start();
	int Stop();

	void Monitor();
};

