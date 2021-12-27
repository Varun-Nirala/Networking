#include <iostream>

#include "verificationTests.h"

using namespace std;

int main(int argc, char *argv[])
{
	nsTestCase::Tester tester;

	tester.test_Address();
	tester.test_Socket();

	//testSocket.runTCP_Test();
	//StestSocket.runAll_Test();
	//nsNW::Address address;
	//address.init("www.google.com", "https", true, AF_INET);
	//address.print();


	return 0;
}
