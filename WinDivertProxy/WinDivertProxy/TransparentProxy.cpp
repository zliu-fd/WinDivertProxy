#include "stdafx.h"
#include "TransparentProxy.h"


TransparentProxy::TransparentProxy(std::string proxyAddr, USHORT proxyPort)
{
	ProxyAddr = inet_addr(proxyAddr.c_str());
	ProxyPort = htons(proxyPort);
	ClientToServerMap = new std::map<EndPoint, EndPoint>();
	Monitoring = false;
	MonitorThread = NULL;
	Debug = false;
}


TransparentProxy::~TransparentProxy(void)
{
	delete ClientToServerMap;
}

int TransparentProxy::Start()
{
	std::cout << "Starting WinDivert ..." << std::endl;
	handle = WinDivertOpen(
		"(outbound and tcp.DstPort == 80) or "
		"(inbound and tcp.SrcPort == 8888)",
		WINDIVERT_LAYER_NETWORK,
		0,
		0);

	if(handle == INVALID_HANDLE_VALUE)
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
		if(!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
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
				if(ntohs(tcphdr->DstPort) == 80)
				{
					EndPoint srcEndPoint;
					srcEndPoint.addr = iphdr->SrcAddr;
					srcEndPoint.port = tcphdr->SrcPort;
					EndPoint dstEndPoint;
					dstEndPoint.addr = iphdr->DstAddr;
					dstEndPoint.port = tcphdr->DstPort;
					(*ClientToServerMap)[srcEndPoint] = dstEndPoint;

					if(Debug)
					{
						in_addr addr;
						addr.S_un.S_addr = iphdr->SrcAddr;
						char* srcAddr = inet_ntoa(addr);
						addr.S_un.S_addr = iphdr->DstAddr;
						char* dstAddr = inet_ntoa(addr);
						addr.S_un.S_addr = ProxyAddr;
						char* proxyAddr = inet_ntoa(addr);
						std::cout << "# Redirect [" << srcAddr << ":" << ntohs(tcphdr->SrcPort) << "  " << dstAddr << ":" << ntohs(tcphdr->DstPort) << "]";
						std::cout << " -> [" << srcAddr << ":" << ntohs(tcphdr->SrcPort) << "  " << proxyAddr << ":" << ntohs(ProxyPort) << "]" << std::endl;
					}

					iphdr->DstAddr = ProxyAddr;
					tcphdr->DstPort = ProxyPort;
					
					DivertHelperCalcChecksums(packet, packetLen, 0);
					UINT writeLen;
					if(!DivertSend(handle, packet, packetLen, &addr, &writeLen))
					{
						std::cout << "Failed to redirect packet." << std::endl;
					}
				}
				else if(ntohs(tcphdr->SrcPort) == 8888)
				{
					EndPoint dstEndPoint;
					dstEndPoint.addr = iphdr->DstAddr;
					dstEndPoint.port = tcphdr->DstPort;
					
					if(ClientToServerMap->find(dstEndPoint) == ClientToServerMap->end())
					{
						if(Debug) std::cout << "x Warning unseen traffics." << std::endl;
					}
					else
					{
						EndPoint originalDstEP = (*ClientToServerMap)[dstEndPoint];
						iphdr->SrcAddr = originalDstEP.addr;
						tcphdr->SrcPort = originalDstEP.port;

						if(Debug)
						{
							in_addr addr;
							addr.S_un.S_addr = iphdr->SrcAddr;
							char* srcAddr = inet_ntoa(addr);
							addr.S_un.S_addr = iphdr->DstAddr;
							char* dstAddr = inet_ntoa(addr);
							addr.S_un.S_addr = ProxyAddr;
							char* proxyAddr = inet_ntoa(addr);
							std::cout << "* Recieved [" << proxyAddr << ":" << ntohs(ProxyPort) << "  " << dstAddr << ":" << ntohs(tcphdr->DstPort) << "]";
							std::cout << " -> [" << srcAddr << ":" << ntohs(tcphdr->SrcPort) << "  " << dstAddr << ":" << ntohs(tcphdr->DstPort) << "]" << std::endl;
						}

						DivertHelperCalcChecksums(packet, packetLen, 0);
						UINT writeLen;
						if(!DivertSend(handle, packet, packetLen, &addr, &writeLen))
						{
							std::cout << "Failed to redirect packet." << std::endl;
						}
					}

				}				
			}
		}
	}
}

void TransparentProxy::Request(unsigned char *packet)
{

}

void TransparentProxy::Response(unsigned char *packet)
{

}