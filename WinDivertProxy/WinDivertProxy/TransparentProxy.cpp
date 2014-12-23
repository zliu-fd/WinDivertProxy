#include "stdafx.h"
#include "TransparentProxy.h"


TransparentProxy::TransparentProxy(std::string proxyAddr, USHORT proxyPort)
{
	ProxyAddr = inet_addr(proxyAddr.c_str());
	ProxyPort = htons(proxyPort);
	ClientToServerMap = new std::map<EndPoint, EndPoint>();
	Monitoring = false;
	MonitorThread = NULL;
	Debug = true;
}


TransparentProxy::~TransparentProxy(void)
{
	delete ClientToServerMap;
}

int TransparentProxy::Start()
{
	std::cout << "Starting WinDivert ..." << std::endl;
	WinDivertHandle = WinDivertOpen(
		"(outbound and tcp.DstPort == 443) or "
		"(inbound and tcp.SrcPort == 443)",
		WINDIVERT_LAYER_NETWORK,
		0,
		0);

	if(WinDivertHandle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER) 
		{ 
			std::cerr << "error: filter syntax error" << std::endl; 
			exit(EXIT_FAILURE); 
		} 
		std::cerr << "error: failed to open the WinDivert device (" << GetLastError() << ")" << std::endl; 
		exit(EXIT_FAILURE); 
	}

	Monitoring = true;
	//MonitorThread = new std::thread(&TransparentProxy::Monitor, this);

	return 0;
}

int TransparentProxy::Stop()
{
	Monitoring = false;
	MonitorThread->join();
	return 0;
}

void TransparentProxy::Monitor()
{
	std::cout << "Start proxy the requests ..." << std::endl;
	unsigned char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;
	UINT packetLen;

	while(Monitoring)
	{
		if(!WinDivertRecv(WinDivertHandle, packet, MAXBUF, &addr, &packetLen))
		{
			continue;
		}else{
			PDIVERT_IPHDR iphdr = NULL;
			PDIVERT_TCPHDR tcphdr = NULL;
			PVOID data = NULL;
			UINT data_len;
			DivertHelperParsePacket(packet, packetLen, &iphdr, NULL, NULL, NULL, &tcphdr, NULL, &data, &data_len);
			if(iphdr != NULL && tcphdr != NULL)
			{
				if(ntohs(tcphdr->DstPort) == 80 || ntohs(tcphdr->DstPort) == 443)
				{
					EndPoint srcEndPoint(iphdr->SrcAddr,  tcphdr->SrcPort);
					EndPoint dstEndPoint(iphdr->DstAddr, tcphdr->DstPort);
					(*ClientToServerMap)[srcEndPoint] = dstEndPoint;
					Request(packet, packetLen, iphdr, tcphdr, addr, data, data_len);
				}
				else if(ntohs(tcphdr->SrcPort) == 443)
				{
					Response(packet, packetLen, iphdr, tcphdr, addr, data, data_len);
				}				
			}
		}
	}
}

void TransparentProxy::Request(unsigned char *packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data, UINT data_len)
{
	if(Debug) LogRedirect(iphdr->SrcAddr, tcphdr->SrcPort, ProxyAddr, ProxyPort, iphdr->DstAddr, tcphdr->DstPort, WINDIVERT_DIRECTION_OUTBOUND);

	/*
	if(ntohs(tcphdr->DstPort) == 443)
	{
		RequestHTTPS(packet, packetLen, iphdr, tcphdr, addr, data, data_len);
	}
	else
	*/
	{
		iphdr->DstAddr = ProxyAddr;
		tcphdr->DstPort = ProxyPort;

		DivertHelperCalcChecksums(packet, packetLen, 0);
		UINT writeLen;
		if(!DivertSend(WinDivertHandle, packet, packetLen, &addr, &writeLen))
		{
			std::cout << "Failed to redirect packet." << std::endl;
			std::cerr << "Error Code: " << GetLastError() << std::endl; 
		}
	}
}

void TransparentProxy::Response(unsigned char* packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data, UINT data_len)
{
	EndPoint dstEndPoint(iphdr->DstAddr, tcphdr->DstPort);

	if(ClientToServerMap->find(dstEndPoint) == ClientToServerMap->end())
	{
		if(Debug) std::cout << "x Warning unseen traffics." << std::endl;
	}
	else
	{
		EndPoint originalDstEP = (*ClientToServerMap)[dstEndPoint];
		iphdr->SrcAddr = originalDstEP.addr;
		tcphdr->SrcPort = originalDstEP.port;

		if(Debug) LogRedirect(iphdr->SrcAddr, tcphdr->SrcPort, ProxyAddr, ProxyPort, iphdr->DstAddr, tcphdr->DstPort, WINDIVERT_DIRECTION_INBOUND);

		DivertHelperCalcChecksums(packet, packetLen, 0);
		UINT writeLen;
		if(!DivertSend(WinDivertHandle, packet, packetLen, &addr, &writeLen))
		{
			std::cout << "Failed to redirect packet." << std::endl;
			std::cerr << "Error Code: " << GetLastError() << std::endl; 
		}
	}
}

void TransparentProxy::RequestHTTPS(unsigned char* packet, UINT packetLen, PDIVERT_IPHDR iphdr, PDIVERT_TCPHDR tcphdr, WINDIVERT_ADDRESS addr, PVOID data, UINT data_len)
{
		char* connectStringFormat = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n";
		char connectionString[100];
		char* endConnectString = "\r\n";

		std::cout << "Data: " << data << std::endl;
		std::cout << "Data_Len: " << data_len << std::endl;

		if(data != NULL && data_len >= 6)
		{
			// TLS HandShake: Client Hello
			unsigned char contentType = ((unsigned char*)data)[0];
			unsigned char TLSMajorVersion = ((unsigned char*)data)[1];
			unsigned char TLSMinorVersion = ((unsigned char*)data)[2];
			unsigned char handshakeType = ((unsigned char*)data)[5];

			if(contentType == 0x16 && TLSMajorVersion == 0x03 && handshakeType == 0x01)
			{
				if(Debug) std::cout << "TLS HandShake: Client Hello captured." << std::endl;
				std::string host = ConvertIP(iphdr->DstAddr) + ":443";
				UINT connectLen = sprintf(connectionString, connectStringFormat, host.c_str(), host.c_str());

				unsigned char connectPacket[MAXBUF];
				
				for(int i = 0; i< packetLen;i++)
				{
					connectPacket[i] = packet[i];
				}

				int connectPacketLen = packetLen;
				for(int i = 0;i < connectLen;i++)
				{
					connectPacket[packetLen - data_len + i] = connectionString[i];
				}
				int delta = connectLen - data_len;
				connectPacketLen += delta;
				
				PDIVERT_IPHDR connectIphdr = (PDIVERT_IPHDR) connectPacket;
				connectIphdr->Length = htons(ntohs(connectIphdr->Length) + delta);
				connectIphdr = NULL;
				PDIVERT_TCPHDR connectTcphdr = NULL;
				PVOID connectData = NULL;

				DivertHelperParsePacket(connectPacket, connectPacketLen, &connectIphdr, NULL, NULL, NULL, &connectTcphdr, NULL, &connectData, &connectLen);
				
				connectIphdr->DstAddr = ProxyAddr;
				connectTcphdr->DstPort = ProxyPort;

				DivertHelperCalcChecksums(connectPacket, connectPacketLen, 0);
				UINT writeLen;
				if(!DivertSend(WinDivertHandle, connectPacket, connectPacketLen, &addr, &writeLen))
				{
					std::cout << "Failed to redirect packet." << std::endl;
					std::cerr << "Error Code: " << GetLastError() << std::endl; 
				}

				std::cout << "Sequence Number" << ntohl(tcphdr->SeqNum) << std::endl;

				unsigned char respPacket[MAXBUF];
				UINT respPacketLen;
				WINDIVERT_ADDRESS respAddr;
				bool established = false;
				int count = 0;
				char* connectEstablished = "HTTP/1.1 200 Connection Established\r\n";
				while(!established){
					WinDivertRecv(WinDivertHandle, respPacket, MAXBUF, &respAddr, &respPacketLen);
					DivertHelperParsePacket(respPacket, respPacketLen, &connectIphdr, NULL, NULL, NULL, &connectTcphdr, NULL, &connectData, &connectLen);
					if(connectLen >= strlen(connectEstablished))
					{
						std::cout << "Count: " << ++count << std::endl;
						char* p = (char*)connectData;
						// std::cout << p << std::endl;
						if(p[0] == 'H' && p[1] == 'T' && p[2] == 'T' && p[3] == 'P')
						{
							established = true;
							std::cout << "Get HTTP 200" << std::endl;
						}
					}
				}
				tcphdr->AckNum = htonl(ntohl(connectTcphdr->SeqNum) + connectLen);
			}
		}

		// Redirect to Proxy
		iphdr->DstAddr = ProxyAddr;
		tcphdr->DstPort = ProxyPort;

		DivertHelperCalcChecksums(packet, packetLen, 0);
		UINT writeLen;
		if(!DivertSend(WinDivertHandle, packet, packetLen, &addr, &writeLen))
		{
			std::cout << "Failed to redirect packet." << std::endl;
			std::cerr << "Error Code: " << GetLastError() << std::endl; 
		}

}

UINT ConstructPacket(unsigned char* buffer, UINT bufferLen, UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort, char* content, UINT contentLen)
{
	return 0;
}

std::string TransparentProxy::ConvertIP(UINT32 addr)
{
	in_addr in_addr;
	in_addr.S_un.S_addr = addr;
	char* pAddr = inet_ntoa(in_addr);
	std::string ipaddr(pAddr);
	return ipaddr;
}

void TransparentProxy::LogRedirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort, int direction){
	if(direction == WINDIVERT_DIRECTION_OUTBOUND)
	{
		std::cout << "O Redirect ";
		std::cout << "[" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << "  " << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]";
		std::cout << " -> [" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << "  " << ConvertIP(proxyAddr) << ":" << ntohs(proxyPort) << "]" << std::endl;
	}
	else if(direction == WINDIVERT_DIRECTION_INBOUND)
	{
		std::cout << "I Received ";
		std::cout << "[" << ConvertIP(proxyAddr) << ":" << ntohs(proxyPort) << "  " << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]";
		std::cout << " -> [" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << "  " << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]" << std::endl;
	}
	else{
		std::cout << "X Error ";
	}
}