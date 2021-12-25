#include <iostream>

#include "verificationTests.h"

using namespace std;

int main(int argc, char *argv[])
{
	nsTestCase::TestSocket testSocket;

	testSocket.runTCP_Test();
	//StestSocket.runAll_Test();

	return 0;
}
