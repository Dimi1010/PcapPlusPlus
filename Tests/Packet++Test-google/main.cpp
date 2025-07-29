#include "pch.h"

#include <iostream>

#include "PcapPlusPlusVersion.h"

#include "TestEnvironment.hpp"

int main(int argc, char* argv[])
{
	using namespace pcpp::testing;

	std::cout << "PcapPlusPlus Packet++Test"
	             "\nPcapPlusPlus version: "
	          << pcpp::getPcapPlusPlusVersionFull()       //
	          << "\nBuilt: " << pcpp::getBuildDateTime()  //
	          << "\nBuilt from: " << pcpp::getGitInfo() << std::endl;

	::testing::InitGoogleMock(&argc, argv);

	std::string dataRoot;  // Empty by default, will use the current directory

	// TODO: Allow setting the data root directory via command line argument or environment variable

	auto packetEnv = std::make_unique<PacketTestEnvironment>(TestDataLoader(dataRoot));
	::testing::AddGlobalTestEnvironment(packetEnv.release());

	return RUN_ALL_TESTS();
}
