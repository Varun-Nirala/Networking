#include <iostream>
#include "socket.h"
#include "server.h"
#include "client.h"

using namespace std;

int main(int argc, char *argv[])
{
	//nsNW::Client client;
	//client.initConnection("INADDR_ANY", "9090", true, true);
	bool ipv4 = true;
	nsNW::Address addr("127.0.0.1", "https", true);
	addr.print();
	return 0;
}