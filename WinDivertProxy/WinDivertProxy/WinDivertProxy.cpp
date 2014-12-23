// WinDivertProxy.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include "TransparentProxy.h"

#define MAXBUF	0xFFFF

int _tmain(int argc, _TCHAR* argv[])
{
	std::string ProxyAddr = "10.156.81.34";
	int ProxyPort = 443;

	TransparentProxy proxy(ProxyAddr, ProxyPort);
	proxy.Start();
	proxy.Monitor();

	return 0;
}

