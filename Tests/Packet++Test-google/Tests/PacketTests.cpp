#include "pch.h"

#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IgmpLayer.h"
#include "DnsLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "RadiusLayer.h"
#include "PacketTrailerLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"

#include "Utils\PacketFactory.hpp"

namespace pcpp
{
	TEST(PacketTest, InsertDataIntoPacket)
	{
		// Creating a packet
		// ~~~~~~~~~~~~~~~~~

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);

		// create the packet
		Packet ip4Packet(1);
		ASSERT_TRUE(ip4Packet.addLayer(&ethLayer));
		ASSERT_TRUE(ip4Packet.addLayer(&ip4Layer));
		ASSERT_TRUE(ip4Packet.addLayer(&payloadLayer));

		ip4Packet.computeCalculateFields();

		// Adding a VLAN layer between Eth and IP
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto vlanLayer = new VlanLayer(100, 0, 0, PCPP_ETHERTYPE_IP);

		ASSERT_TRUE(ip4Packet.insertLayer(&ethLayer, vlanLayer, true));
		ASSERT_EQ(ethLayer.getDestMac(), dstMac);
		ASSERT_EQ(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
		ASSERT_EQ(ip4Layer.getDstIPAddress(), ipDst);
		ASSERT_EQ(ip4Layer.getSrcIPAddress(), ipSrc);
		ASSERT_EQ(payloadLayer.getPayload()[3], 0x04);

		// Adding another Eth layer at the beginning of the packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		MacAddress srcMac2("cc:cc:cc:cc:cc:cc");
		MacAddress dstMac2("dd:dd:dd:dd:dd:dd");
		auto ethLayer2 = new EthLayer(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(ip4Packet.insertLayer(nullptr, ethLayer2, true));

		ASSERT_EQ(ip4Packet.getFirstLayer(), ethLayer2, ptr);
		ASSERT_EQ(ip4Packet.getFirstLayer()->getNextLayer(), &ethLayer, ptr);
		ASSERT_EQ(ip4Packet.getFirstLayer()->getNextLayer()->getNextLayer(), vlanLayer, ptr);
		ASSERT_EQ(ethLayer.getDestMac(), dstMac);
		ASSERT_EQ(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
		ASSERT_EQ(ip4Layer.getDstIPAddress(), ipDst);
		ASSERT_EQ(ip4Layer.getSrcIPAddress(), ipSrc);
		ASSERT_EQ(payloadLayer.getPayload()[3], 0x04);

		// Adding a TCP layer at the end of the packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto tcpLayer = new TcpLayer((uint16_t)12345, (uint16_t)80);
		ASSERT_TRUE(ip4Packet.insertLayer(&payloadLayer, tcpLayer, true));

		// Create a new packet and use insertLayer for the first layer in packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		EthLayer ethLayer3(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
		Packet testPacket(1);
		ASSERT_TRUE(testPacket.insertLayer(nullptr, &ethLayer3));
		ASSERT_EQ(testPacket.getFirstLayer(), &ethLayer3);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), nullptr);
		ASSERT_EQ(ethLayer3.getDestMac(), dstMac2);
	}

	TEST(PacketTest, CreatePacketFromBuffer)
	{
		size_t bufferSize = 46;
		auto buffer = std::make_unique<uint8_t[]>(bufferSize);
		memset(buffer.get(), 0, bufferSize);

		auto newPacket = std::make_unique<Packet>(buffer.get(), bufferSize);

		// Create the packet layers

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(newPacket->addLayer(&ethLayer));

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
		ASSERT_TRUE(newPacket->addLayer(&ip4Layer));

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);
		ASSERT_TRUE(newPacket->addLayer(&payloadLayer));

		Logger::getInstance().suppressLogs();

		// Inserting a new layer should fail because the size of the new layer exceeds the buffer size
		TcpLayer tcpLayer(12345, 80);
		ASSERT_FALSE(newPacket->insertLayer(&ip4Layer, &tcpLayer));

		// Extending the IPv4 layer should fail because the size of the new option exceeds the buffer size
		IPv4Option newOption = ip4Layer.addOption(IPv4OptionBuilder(IPV4OPT_RouterAlert, (uint16_t)100));
		EXPECT_TRUE(newOption.isNull());

		Logger::getInstance().enableLogs();

		newPacket->computeCalculateFields();

		// Delete the packet - the buffer should not be freed
		// delete newPacket;

		std::string expectedHexString =
		    "bbbbbbbbbbbbaaaaaaaaaaaa08004500001e00000000000690b101010101141414140102030405060708090a0000";
		EXPECT_EQ(byteArrayToHexString(buffer.get(), bufferSize), expectedHexString);
	}

	TEST(PacketTest, InsertVlanToPacket)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");

		VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);

		Packet tcpPacket(rawPacket1.get());

		ASSERT_TRUE(tcpPacket.insertLayer(tcpPacket.getFirstLayer(), &vlanLayer));

		EXPECT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 78);
		EXPECT_EQ(tcpPacket.getFirstLayer()->getNextLayer(), &vlanLayer);
		EXPECT_NE(vlanLayer.getNextLayer(), nullptr);
		EXPECT_EQ(vlanLayer.getNextLayer()->getProtocol(), IPv4);
	}

	TEST(PacketTest, RemoveLayerTest)
	{
		// parse packet and remove layers
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketNoOptions.dat");
		Packet tcpPacket(rawPacket1.get());

		// a. Remove layer from the middle
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(tcpPacket.removeLayer(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getLayerOfType<IPv4Layer>(), nullptr);
		ASSERT_EQ(tcpPacket.getFirstLayer()->getNextLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 271);

		// b. Remove first layer
		// ~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(tcpPacket.removeFirstLayer());
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getFirstLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getFirstLayer()->getNextLayer()->getNextLayer(), nullptr);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 257);

		// c. Remove last layer
		// ~~~~~~~~~~~~~~~~~~~~
		ASSERT_TRUE(tcpPacket.removeLastLayer());
		ASSERT_FALSE(tcpPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(tcpPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(tcpPacket.getFirstLayer(), tcpPacket.getLastLayer());
		ASSERT_EQ(tcpPacket.getFirstLayer()->getProtocol(), TCP);
		ASSERT_EQ(tcpPacket.getRawPacket()->getRawDataLen(), 20);

		// d. Remove a second layer of the same type
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/Vxlan1.dat");

		Packet vxlanPacket(rawPacket2.get());
		ASSERT_TRUE(vxlanPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(vxlanPacket.removeLayer(Ethernet, 1));
		ASSERT_TRUE(vxlanPacket.removeLayer(IPv4, 1));
		ASSERT_TRUE(vxlanPacket.removeLayer(ICMP));
		vxlanPacket.computeCalculateFields();
		ASSERT_TRUE(vxlanPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(vxlanPacket.isPacketOfType(VXLAN));
		ASSERT_EQ(vxlanPacket.getRawPacket()->getRawDataLen(), 50);

		// e. Remove a layer that doesn't exist
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		Logger::getInstance().suppressLogs();
		ASSERT_FALSE(vxlanPacket.removeLayer(HTTPRequest));
		ASSERT_FALSE(vxlanPacket.removeLayer(Ethernet, 1));
		Logger::getInstance().enableLogs();

		// create packet and remove layers
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		Packet testPacket(10);

		MacAddress srcMac("aa:aa:aa:aa:aa:aa");
		MacAddress dstMac("bb:bb:bb:bb:bb:bb");
		EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(testPacket.addLayer(&ethLayer));

		IPv4Address ipSrc("1.1.1.1");
		IPv4Address ipDst("20.20.20.20");
		IPv4Layer ip4Layer(ipSrc, ipDst);
		ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
		ASSERT_TRUE(testPacket.addLayer(&ip4Layer));

		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);
		ASSERT_TRUE(testPacket.addLayer(&payloadLayer));

		// a. remove first layer
		// ~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(Ethernet));
		ASSERT_EQ(testPacket.getFirstLayer(), &ip4Layer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer()->getNextLayer(), nullptr);
		ASSERT_FALSE(testPacket.isPacketOfType(Ethernet));
		ASSERT_TRUE(testPacket.isPacketOfType(IPv4));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 30);

		// b. remove last layer
		// ~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(GenericPayload));
		ASSERT_EQ(testPacket.getFirstLayer(), &ip4Layer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), nullptr);
		ASSERT_TRUE(testPacket.isPacketOfType(IPv4));
		ASSERT_FALSE(testPacket.isPacketOfType(Ethernet));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 20);

		// c. insert a layer
		// ~~~~~~~~~~~~~~~~~

		VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(testPacket.insertLayer(nullptr, &vlanLayer));
		ASSERT_EQ(testPacket.getFirstLayer(), &vlanLayer);
		ASSERT_EQ(testPacket.getFirstLayer()->getNextLayer(), &ip4Layer, ptr);
		ASSERT_TRUE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 24);

		// d. remove the remaining layers (packet remains empty!)
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		ASSERT_TRUE(testPacket.removeLayer(IPv4));
		ASSERT_EQ(testPacket.getFirstLayer(), &vlanLayer);
		ASSERT_FALSE(testPacket.isPacketOfType(IPv4));
		ASSERT_TRUE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 4);
		ASSERT_TRUE(testPacket.removeLayer(VLAN));
		ASSERT_FALSE(testPacket.isPacketOfType(VLAN));
		ASSERT_EQ(testPacket.getRawPacket()->getRawDataLen(), 0);

		// Detach layer and add it to another packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		// a. create a layer nad a packet and move it to another packet
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		EthLayer eth(MacAddress("0a:00:27:00:00:15"), MacAddress("0a:00:27:00:00:16"));
		Packet packet1, packet2;
		ASSERT_TRUE(packet1.addLayer(&eth));
		ASSERT_EQ(packet1.getRawPacket()->getRawDataLen(), 14);
		ASSERT_TRUE(packet1.detachLayer(&eth));
		ASSERT_EQ(packet1.getRawPacket()->getRawDataLen(), 0);
		ASSERT_EQ(packet2.getRawPacket()->getRawDataLen(), 0);
		ASSERT_TRUE(packet2.addLayer(&eth));
		ASSERT_EQ(packet2.getRawPacket()->getRawDataLen(), 14);

		// b. parse a packet, detach a layer and move it to another packet
		// c. detach a second instance of the the same protocol
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		auto rawPacket3 = test::createPacketFromHexResource("PacketExamples/Vxlan1.dat");

		Packet vxlanPacketOrig(rawPacket3.get());
		EthLayer* vxlanEthLayer = dynamic_cast<EthLayer*>(vxlanPacketOrig.detachLayer(Ethernet, 1));
		IcmpLayer* vxlanIcmpLayer = dynamic_cast<IcmpLayer*>(vxlanPacketOrig.detachLayer(ICMP));
		IPv4Layer* vxlanIP4Layer = dynamic_cast<IPv4Layer*>(vxlanPacketOrig.detachLayer(IPv4, 1));
		ASSERT_NE(vxlanEthLayer, nullptr) << "Failed detaching Ethernet layer from vxlan packet";
		ASSERT_NE(vxlanIcmpLayer, nullptr) << "Failed detaching ICPM layer from vxlan packet";
		ASSERT_NE(vxlanIP4Layer, nullptr) << "Failed detaching IPv4 layer from vxlan packet";

		vxlanPacketOrig.computeCalculateFields();
		ASSERT_FALSE(vxlanEthLayer->isAllocatedToPacket());
		ASSERT_FALSE(vxlanIcmpLayer->isAllocatedToPacket());
		ASSERT_FALSE(vxlanIP4Layer->isAllocatedToPacket());
		ASSERT_NE(vxlanPacketOrig.getLayerOfType(Ethernet), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(Ethernet, 1), nullptr);
		ASSERT_NE(vxlanPacketOrig.getLayerOfType(IPv4), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(IPv4, 1), nullptr);
		ASSERT_EQ(vxlanPacketOrig.getLayerOfType(ICMP), nullptr);

		Packet packetWithoutTunnel;
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanEthLayer));
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIP4Layer));
		ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIcmpLayer));
		packetWithoutTunnel.computeCalculateFields();

		auto buffer4 = test::PacketTestEnvironment::getCurrent().getDataLoader().loadResource(
		    "PacketExamples/IcmpWithoutTunnel.dat", test::ResourceType::HexData);

		ASSERT_EQ(packetWithoutTunnel.getRawPacket()->getRawDataLen(), buffer4.size());

		// TODO: Improve this comparison
		EXPECT_TRUE(std::memcmp(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4.data(), buffer4.size()) == 0);
		// ASSERT_BUF_COMPARE(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4, bufferLength4);
	}

	TEST(PacketTest, CopyLayerAndPacketTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PacketLayerLookupTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	// TODO: Move test above PacketTest fixture
	TEST(RawPacketTest, RawPacketTimeStampSetterTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, ParsePartialPacketTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PacketTrailerTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ResizeLayerTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	TEST(PacketTest, PrintPacketAndLayersTest)
	{
		FAIL() << "This test is not implemented yet";
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ProtocolFamilyMembershipTest)
	{
		auto rawPacket = test::createPacketFromHexResource("PacketExamples/TwoHttpRequests1.dat");
		Packet packet(rawPacket.get());

		auto ipV4Layer = packet.getLayerOfType<IPv4Layer>();
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IP));
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IPv4));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IPv6));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(pcpp::HTTP));

		auto httpLayer = packet.getLayerOfType<HttpRequestLayer>();
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTP));
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTPRequest));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTPResponse));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(pcpp::IP));
	}

	TEST(PacketTest, ParseUntilLayer)
	{
		auto rawPacket0 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");
		Packet packet0(rawPacket0.get(), OsiModelPhysicalLayer);
		EXPECT_EQ(packet0.getLastLayer(), packet0.getFirstLayer());

		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions3.dat");
		Packet packet1(rawPacket1.get(), OsiModelTransportLayer);
		EXPECT_EQ(packet1.getLastLayer()->getOsiModelLayer(), OsiModelTransportLayer);
	}
}  // namespace pcpp