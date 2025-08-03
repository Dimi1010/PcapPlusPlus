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

	TEST(PacketTest, RemoveLayer)
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

		auto buffer4 = test::PacketTestEnvironment::getCurrent().getDataLoader().loadResourceToVector(
		    "PacketExamples/IcmpWithoutTunnel.dat", test::ResourceType::HexData);

		EXPECT_TRUE(test::BuffersMatch(packetWithoutTunnel.getRawPacket()->getRawData(),
		                               packetWithoutTunnel.getRawPacket()->getRawDataLen(), buffer4.data(),
		                               buffer4.size()));
	}

	TEST(PacketTest, CopyLayerAndPacket)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/TwoHttpResponses1.dat");

		Packet sampleHttpPacket(rawPacket1.get());

		// RawPacket copy c'tor / assignment operator test
		//-----------------------------------------------
		RawPacket copyRawPacket;
		copyRawPacket = *rawPacket1;
		EXPECT_EQ(copyRawPacket.getRawDataLen(), rawPacket1->getRawDataLen());
		EXPECT_NE(copyRawPacket.getRawData(), rawPacket1->getRawData());
		EXPECT_TRUE(test::BuffersMatch(copyRawPacket.getRawData(), copyRawPacket.getRawDataLen(),
		                               rawPacket1->getRawData(), rawPacket1->getRawDataLen()));

		// EthLayer copy c'tor test
		//------------------------
		EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<EthLayer>();
		EXPECT_NE(sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayload(), ethLayer.getLayerPayload());
		EXPECT_TRUE(test::BuffersMatch(ethLayer.getLayerPayload(),
		                               sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayload(),
		                               sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayloadSize()));

		// TcpLayer copy c'tor test
		//------------------------
		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/TcpPacketWithOptions2.dat");

		Packet sampleTcpPacketWithOptions(rawPacket2.get());
		TcpLayer tcpLayer = *sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>();
		EXPECT_NE(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getData(), tcpLayer.getData());
		EXPECT_TRUE(test::BuffersMatch(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getData(),
		                               tcpLayer.getData(),
		                               sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getDataLen()));

		EXPECT_EQ(tcpLayer.getTcpOptionCount(),
		          sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionCount());

		EXPECT_NE(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()
		              ->getTcpOption(TcpOptionEnumType::Timestamp)
		              .getRecordBasePtr(),
		          tcpLayer.getTcpOption(TcpOptionEnumType::Timestamp).getRecordBasePtr());

		EXPECT_EQ(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOption(TcpOptionEnumType::Timestamp),
		          tcpLayer.getTcpOption(TcpOptionEnumType::Timestamp));

		// HttpLayer copy c'tor test
		//--------------------------

		HttpResponseLayer* sampleHttpLayer = sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
		HttpResponseLayer httpResLayer = *sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
		EXPECT_TRUE(sampleHttpLayer->getFirstLine() != httpResLayer.getFirstLine());
		EXPECT_EQ(sampleHttpLayer->getFirstLine()->getStatusCode(), httpResLayer.getFirstLine()->getStatusCode());
		EXPECT_EQ(sampleHttpLayer->getFirstLine()->getSize(), httpResLayer.getFirstLine()->getSize());
		EXPECT_EQ(sampleHttpLayer->getFirstLine()->getVersion(), httpResLayer.getFirstLine()->getVersion());

		HeaderField* curFieldInSample = sampleHttpLayer->getFirstField();
		HeaderField* curFieldInCopy = httpResLayer.getFirstField();
		while (curFieldInSample != nullptr && curFieldInCopy != nullptr)
		{
			EXPECT_TRUE(curFieldInCopy != curFieldInSample);
			EXPECT_EQ(curFieldInSample->getFieldName(), curFieldInCopy->getFieldName());
			EXPECT_EQ(curFieldInSample->getFieldValue(), curFieldInCopy->getFieldValue());
			EXPECT_EQ(curFieldInSample->getFieldSize(), curFieldInCopy->getFieldSize());

			curFieldInSample = sampleHttpLayer->getNextField(curFieldInSample);
			curFieldInCopy = sampleHttpLayer->getNextField(curFieldInCopy);
		}

		EXPECT_EQ(curFieldInSample, nullptr);
		EXPECT_EQ(curFieldInCopy, nullptr);

		// Packet copy c'tor test - Ethernet
		//---------------------------------

		Packet samplePacketCopy(sampleHttpPacket);
		EXPECT_TRUE(samplePacketCopy.getFirstLayer() != sampleHttpPacket.getFirstLayer());
		EXPECT_TRUE(samplePacketCopy.getLastLayer() != sampleHttpPacket.getLastLayer());
		EXPECT_TRUE(samplePacketCopy.getRawPacket() != sampleHttpPacket.getRawPacket());

		EXPECT_EQ(samplePacketCopy.getRawPacket()->getRawDataLen(), sampleHttpPacket.getRawPacket()->getRawDataLen());
		EXPECT_TRUE(test::BuffersMatch(
		    samplePacketCopy.getRawPacket()->getRawData(), samplePacketCopy.getRawPacket()->getRawDataLen(),
		    sampleHttpPacket.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawDataLen()));

		EXPECT_TRUE(samplePacketCopy.isPacketOfType(Ethernet));
		EXPECT_TRUE(samplePacketCopy.isPacketOfType(IPv4));
		EXPECT_TRUE(samplePacketCopy.isPacketOfType(TCP));
		EXPECT_TRUE(samplePacketCopy.isPacketOfType(HTTPResponse));
		Layer* curSamplePacketLayer = sampleHttpPacket.getFirstLayer();
		Layer* curPacketCopyLayer = samplePacketCopy.getFirstLayer();
		while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
		{
			EXPECT_EQ(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol());
			EXPECT_EQ(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
			EXPECT_EQ(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
			EXPECT_EQ(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
			EXPECT_TRUE(test::BuffersMatch(curSamplePacketLayer->getData(), curPacketCopyLayer->getData(),
			                               curSamplePacketLayer->getDataLen()));
			curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
			curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
		}

		auto samplePacketCopyHttpResponseLayer = samplePacketCopy.getLayerOfType<HttpResponseLayer>();
		auto contentTypeField = samplePacketCopyHttpResponseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		ASSERT_NE(samplePacketCopyHttpResponseLayer->insertField(contentTypeField, "X-Forwarded-For", "10.20.30.40"),
		          nullptr);

		samplePacketCopy = sampleHttpPacket;
		samplePacketCopyHttpResponseLayer = samplePacketCopy.getLayerOfType<HttpResponseLayer>();
		contentTypeField = samplePacketCopyHttpResponseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		ASSERT_NE(samplePacketCopyHttpResponseLayer->insertField(contentTypeField, "X-Forwarded-For", "10.20.30.40"),
		          nullptr);

		EXPECT_EQ(curSamplePacketLayer, nullptr);
		EXPECT_EQ(curPacketCopyLayer, nullptr);

		// Packet copy c'tor test - Null/Loopback
		//--------------------------------------

		auto rawPacket3 = test::createPacketFromHexResource(
		    "PacketExamples/NullLoopback1.dat", test::PacketFactory().withLinkType(LinkLayerType::LINKTYPE_NULL));

		Packet nullLoopbackPacket(rawPacket3.get());

		Packet nullLoopbackPacketCopy(nullLoopbackPacket);

		EXPECT_TRUE(nullLoopbackPacketCopy.getFirstLayer() != nullLoopbackPacket.getFirstLayer());
		EXPECT_TRUE(nullLoopbackPacketCopy.getLastLayer() != nullLoopbackPacket.getLastLayer());
		EXPECT_TRUE(nullLoopbackPacketCopy.getRawPacket() != nullLoopbackPacket.getRawPacket());

		EXPECT_EQ(nullLoopbackPacketCopy.getRawPacket()->getRawDataLen(),
		          nullLoopbackPacket.getRawPacket()->getRawDataLen());
		EXPECT_TRUE(test::BuffersMatch(
		    nullLoopbackPacketCopy.getRawPacket()->getRawData(), nullLoopbackPacketCopy.getRawPacket()->getRawDataLen(),
		    nullLoopbackPacket.getRawPacket()->getRawData(), nullLoopbackPacket.getRawPacket()->getRawDataLen()));

		EXPECT_EQ(nullLoopbackPacketCopy.getRawPacket()->getLinkLayerType(), LINKTYPE_NULL);
		EXPECT_EQ(nullLoopbackPacketCopy.getFirstLayer()->getProtocol(), NULL_LOOPBACK);

		curSamplePacketLayer = nullLoopbackPacket.getFirstLayer();
		curPacketCopyLayer = nullLoopbackPacketCopy.getFirstLayer();
		while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
		{
			EXPECT_EQ(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol());
			EXPECT_EQ(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
			EXPECT_EQ(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
			EXPECT_EQ(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
			curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
			curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
		}

		// Packet copy c'tor test - SLL
		//----------------------------

		auto rawPacket4 = test::createPacketFromHexResource(
		    "PacketExamples/SllPacket2.dat", test::PacketFactory().withLinkType(LinkLayerType::LINKTYPE_LINUX_SLL));

		Packet sllPacket(rawPacket4.get());

		Packet sllPacketCopy(sllPacket);

		EXPECT_TRUE(sllPacketCopy.getFirstLayer() != sllPacket.getFirstLayer());
		EXPECT_TRUE(sllPacketCopy.getLastLayer() != sllPacket.getLastLayer());
		EXPECT_TRUE(sllPacketCopy.getRawPacket() != sllPacket.getRawPacket());

		EXPECT_EQ(sllPacketCopy.getRawPacket()->getRawDataLen(), sllPacket.getRawPacket()->getRawDataLen());
		EXPECT_TRUE(test::BuffersMatch(
		    sllPacketCopy.getRawPacket()->getRawData(), sllPacketCopy.getRawPacket()->getRawDataLen(),
		    sllPacket.getRawPacket()->getRawData(), sllPacket.getRawPacket()->getRawDataLen()));

		EXPECT_EQ(sllPacketCopy.getRawPacket()->getLinkLayerType(), LINKTYPE_LINUX_SLL);
		EXPECT_EQ(sllPacketCopy.getFirstLayer()->getProtocol(), SLL);

		curSamplePacketLayer = sllPacket.getFirstLayer();
		curPacketCopyLayer = sllPacketCopy.getFirstLayer();
		while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
		{
			EXPECT_EQ(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol());
			EXPECT_EQ(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
			EXPECT_EQ(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
			EXPECT_EQ(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
			curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
			curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
		}

		// DnsLayer copy c'tor and operator= test
		//--------------------------------------

		auto rawPacket5 = test::createPacketFromHexResource("PacketExamples/Dns2.dat");

		Packet sampleDnsPacket(rawPacket5.get());

		DnsLayer* origDnsLayer = sampleDnsPacket.getLayerOfType<DnsLayer>();
		ASSERT_NE(origDnsLayer, nullptr);
		DnsLayer copyDnsLayer(*origDnsLayer);
		EXPECT_EQ(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount());
		EXPECT_EQ(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName());
		EXPECT_EQ(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType());

		EXPECT_EQ(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount());
		EXPECT_EQ(copyDnsLayer.getAuthority("Yaels-iPhone.local", true)->getData()->toString(),
		          origDnsLayer->getAuthority("Yaels-iPhone.local", true)->getData()->toString());

		EXPECT_EQ(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(),
		          origDnsLayer->getAdditionalRecord("", true)->getData()->toString());

		copyDnsLayer.addQuery("bla", DNS_TYPE_A, DNS_CLASS_ANY);
		IPv4DnsResourceData ipv4DnsData(std::string("1.1.1.1"));
		copyDnsLayer.addAnswer("bla", DNS_TYPE_A, DNS_CLASS_ANY, 123, &ipv4DnsData);

		copyDnsLayer = *origDnsLayer;

		EXPECT_EQ(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount());
		EXPECT_EQ(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName());
		EXPECT_EQ(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType(), enum);

		EXPECT_EQ(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount());
		EXPECT_EQ(copyDnsLayer.getAuthority(".local", false)->getData()->toString(),
		          origDnsLayer->getAuthority("iPhone.local", false)->getData()->toString());

		EXPECT_EQ(copyDnsLayer.getAnswerCount(), origDnsLayer->getAnswerCount());

		EXPECT_EQ(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(),
		          origDnsLayer->getAdditionalRecord("", true)->getData()->toString());
	}

	TEST(PacketTest, PacketLayerLookup)
	{
		{
			auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/radius_1.dat");
			Packet radiusPacket(rawPacket1.get());

			RadiusLayer* radiusLayer = radiusPacket.getLayerOfType<RadiusLayer>(true);
			EXPECT_NE(radiusLayer, nullptr);

			EthLayer* ethLayer = radiusPacket.getLayerOfType<EthLayer>(true);
			EXPECT_NE(ethLayer, nullptr);

			IPv4Layer* ipLayer = radiusPacket.getPrevLayerOfType<IPv4Layer>(radiusLayer);
			EXPECT_NE(ipLayer, nullptr);

			TcpLayer* tcpLayer = radiusPacket.getPrevLayerOfType<TcpLayer>(ipLayer);
			EXPECT_EQ(tcpLayer, nullptr);
		}

		{
			auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/Vxlan1.dat");
			Packet vxlanPacket(rawPacket2.get());

			// get the last IPv4 layer
			IPv4Layer* ipLayer = vxlanPacket.getLayerOfType<IPv4Layer>(true);
			ASSERT_NE(ipLayer, nullptr);
			EXPECT_EQ(ipLayer->getSrcIPAddress(), IPv4Address("192.168.203.3"));
			EXPECT_EQ(ipLayer->getDstIPAddress(), IPv4Address("192.168.203.5"));

			// get the first IPv4 layer
			ipLayer = vxlanPacket.getPrevLayerOfType<IPv4Layer>(ipLayer);
			ASSERT_NE(ipLayer, nullptr);
			EXPECT_EQ(ipLayer->getSrcIPAddress(), IPv4Address("192.168.203.1"));
			EXPECT_EQ(ipLayer->getDstIPAddress(), IPv4Address("192.168.202.1"));

			// try to get one more IPv4 layer
			EXPECT_EQ(vxlanPacket.getPrevLayerOfType<IPv4Layer>(ipLayer), nullptr);

			// get the first layer
			EthLayer* ethLayer = vxlanPacket.getPrevLayerOfType<EthLayer>(ipLayer);
			ASSERT_NE(ethLayer, nullptr);
			EXPECT_EQ(vxlanPacket.getPrevLayerOfType<EthLayer>(ethLayer), nullptr);
			EXPECT_EQ(vxlanPacket.getPrevLayerOfType<EthLayer>(vxlanPacket.getFirstLayer()), nullptr);

			// try to get nonexistent layer
			EXPECT_EQ(vxlanPacket.getLayerOfType<RadiusLayer>(true), nullptr);
		}
	}

	// TODO: Move test above PacketTest fixture
	TEST(RawPacketTest, RawPacketTimeStampSetter)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/IPv6UdpPacket.dat");

		timespec expected_ts;

		{
			SCOPED_TRACE("Testing usec-precision setter");
			timeval usec_test_time;

			usec_test_time.tv_sec = 1583840642;  // 10.03.2020 15:44
			usec_test_time.tv_usec = 111222;
			expected_ts.tv_sec = usec_test_time.tv_sec;
			expected_ts.tv_nsec = usec_test_time.tv_usec * 1000;

			EXPECT_TRUE(rawPacket1->setPacketTimeStamp(usec_test_time));
			EXPECT_EQ(rawPacket1->getPacketTimeStamp().tv_sec, expected_ts.tv_sec);
			EXPECT_EQ(rawPacket1->getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec);
		}

		{
			SCOPED_TRACE("Testing nsec-precision setter");
			timespec nsec_test_time;

			nsec_test_time.tv_sec = 1583842105;  // 10.03.2020 16:08
			nsec_test_time.tv_nsec = 111222987;
			expected_ts = nsec_test_time;

			ASSERT_TRUE(rawPacket1->setPacketTimeStamp(nsec_test_time));
			EXPECT_EQ(rawPacket1->getPacketTimeStamp().tv_sec, expected_ts.tv_sec);
			EXPECT_EQ(rawPacket1->getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec);
		}
	}

	TEST(PacketTest, ParsePartialPacket)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/SSL-ClientHello1.dat");
		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/IGMPv1_1.dat");
		auto rawPacket3 = test::createPacketFromHexResource("PacketExamples/TwoHttpRequests1.dat");
		auto rawPacket4 = test::createPacketFromHexResource("PacketExamples/PPPoESession2.dat");
		auto rawPacket5 = test::createPacketFromHexResource("PacketExamples/TwoHttpRequests2.dat");
		auto rawPacket6 = test::createPacketFromHexResource("PacketExamples/IcmpTimestampRequest.dat");
		auto rawPacket7 = test::createPacketFromHexResource("PacketExamples/GREv0_2.dat");

		Packet sslPacket(rawPacket1.get(), TCP);
		Packet igmpPacket(rawPacket2.get(), IP);
		Packet httpPacket(rawPacket3.get(), OsiModelTransportLayer);
		Packet pppoePacket(rawPacket4.get(), OsiModelDataLinkLayer);
		Packet httpPacket2(rawPacket5.get(), OsiModelPresentationLayer);
		Packet icmpPacket(rawPacket6.get(), OsiModelNetworkLayer);
		Packet grePacket(rawPacket7.get(), GRE);

		EXPECT_TRUE(sslPacket.isPacketOfType(IPv4));
		EXPECT_TRUE(sslPacket.isPacketOfType(TCP));
		EXPECT_FALSE(sslPacket.isPacketOfType(SSL));
		EXPECT_NE(sslPacket.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(sslPacket.getLayerOfType<IPv4Layer>(), nullptr);
		EXPECT_NE(sslPacket.getLayerOfType<TcpLayer>(), nullptr);
		EXPECT_EQ(sslPacket.getLayerOfType<TcpLayer>()->getNextLayer(), nullptr);
		EXPECT_EQ(sslPacket.getLayerOfType<SSLHandshakeLayer>(), nullptr);
		EXPECT_EQ(sslPacket.getLayerOfType<PayloadLayer>(), nullptr);

		EXPECT_TRUE(igmpPacket.isPacketOfType(IPv4));
		EXPECT_TRUE(igmpPacket.isPacketOfType(Ethernet));
		EXPECT_FALSE(igmpPacket.isPacketOfType(IGMP));
		EXPECT_NE(igmpPacket.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(igmpPacket.getLayerOfType<IPv4Layer>(), nullptr);
		EXPECT_EQ(igmpPacket.getLayerOfType<IgmpV1Layer>(), nullptr);
		EXPECT_EQ(igmpPacket.getLayerOfType<PayloadLayer>(), nullptr);

		EXPECT_TRUE(httpPacket.isPacketOfType(IPv4));
		EXPECT_TRUE(httpPacket.isPacketOfType(Ethernet));
		EXPECT_TRUE(httpPacket.isPacketOfType(TCP));
		EXPECT_FALSE(httpPacket.isPacketOfType(HTTP));
		EXPECT_NE(httpPacket.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(httpPacket.getLayerOfType<IPv4Layer>(), nullptr);
		EXPECT_NE(httpPacket.getLayerOfType<TcpLayer>(), nullptr);
		EXPECT_EQ(httpPacket.getLayerOfType<HttpRequestLayer>(), nullptr);
		EXPECT_EQ(httpPacket.getLayerOfType<PayloadLayer>(), nullptr);

		EXPECT_TRUE(pppoePacket.isPacketOfType(Ethernet));
		EXPECT_TRUE(pppoePacket.isPacketOfType(PPPoESession));
		EXPECT_FALSE(pppoePacket.isPacketOfType(IPv6));
		EXPECT_FALSE(pppoePacket.isPacketOfType(UDP));
		EXPECT_NE(pppoePacket.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(pppoePacket.getLayerOfType<PPPoESessionLayer>(), nullptr);
		EXPECT_EQ(pppoePacket.getLayerOfType<IPv6Layer>(), nullptr);

		EXPECT_TRUE(httpPacket2.isPacketOfType(IPv4));
		EXPECT_TRUE(httpPacket2.isPacketOfType(Ethernet));
		EXPECT_TRUE(httpPacket2.isPacketOfType(TCP));
		EXPECT_FALSE(httpPacket2.isPacketOfType(HTTP));
		EXPECT_NE(httpPacket2.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(httpPacket2.getLayerOfType<IPv4Layer>(), nullptr);
		EXPECT_NE(httpPacket2.getLayerOfType<TcpLayer>(), nullptr);
		EXPECT_EQ(httpPacket2.getLayerOfType<TcpLayer>()->getNextLayer(), nullptr);
		EXPECT_EQ(httpPacket2.getLastLayer()->getProtocol(), TCP);
		EXPECT_EQ(httpPacket2.getLayerOfType<HttpRequestLayer>(), nullptr);
		EXPECT_EQ(httpPacket2.getLayerOfType<PayloadLayer>(), nullptr);

		EXPECT_TRUE(icmpPacket.isPacketOfType(IPv4));
		EXPECT_TRUE(icmpPacket.isPacketOfType(Ethernet));
		EXPECT_TRUE(icmpPacket.isPacketOfType(ICMP));
		EXPECT_NE(icmpPacket.getLayerOfType<EthLayer>(), nullptr);
		EXPECT_NE(icmpPacket.getLayerOfType<IPv4Layer>(), nullptr);
		EXPECT_NE(icmpPacket.getLayerOfType<IcmpLayer>(), nullptr);

		EXPECT_TRUE(grePacket.isPacketOfType(Ethernet));
		EXPECT_TRUE(grePacket.isPacketOfType(IPv4));
		EXPECT_TRUE(grePacket.isPacketOfType(GREv0));
		EXPECT_FALSE(grePacket.isPacketOfType(UDP));
		Layer* curLayer = grePacket.getFirstLayer();
		ASSERT_NE(curLayer, nullptr);
		EXPECT_EQ(curLayer->getProtocol(), Ethernet);
		curLayer = curLayer->getNextLayer();
		ASSERT_NE(curLayer, nullptr);
		EXPECT_EQ(curLayer->getProtocol(), IPv4);
		curLayer = curLayer->getNextLayer();
		ASSERT_NE(curLayer, nullptr);
		EXPECT_EQ(curLayer->getProtocol(), GREv0);
		curLayer = curLayer->getNextLayer();
		EXPECT_EQ(curLayer, nullptr);
	}

	TEST(PacketTest, PacketTrailer)
	{
		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/packet_trailer_arp.dat");
		auto rawPacket2 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv4.dat");
		auto rawPacket3 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv6.dat");
		auto rawPacket4 = test::createPacketFromHexResource("PacketExamples/packet_trailer_pppoed.dat");
		auto rawPacket5 = test::createPacketFromHexResource("PacketExamples/packet_trailer_ipv6.dat");

		Packet trailerArpPacket(rawPacket1.get());
		Packet trailerIPv4Packet(rawPacket2.get());
		Packet trailerIPv6Packet(rawPacket3.get());
		Packet trailerPPPoEDPacket(rawPacket4.get());
		Packet trailerIPv6Packet2(rawPacket5.get());

		EXPECT_TRUE(trailerArpPacket.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerIPv4Packet.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerIPv6Packet.isPacketOfType(PacketTrailer));
		EXPECT_TRUE(trailerPPPoEDPacket.isPacketOfType(PacketTrailer));

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 18);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 6);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 4);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen(), 28);

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(),
		          "742066726f6d2062726964676500203d3d20");
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(), "0101080a0000");
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(), "cdfcf105");
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString(),
		          "00000000000000000000000000000000000000000000000000000000");

		EXPECT_EQ(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[3], 0x72);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[2], 0x8);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[1], 0xfc);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[12], 0);

		EthLayer* ethLayer = trailerIPv4Packet.getLayerOfType<EthLayer>();
		IPv4Layer* ip4Layer = trailerIPv4Packet.getLayerOfType<IPv4Layer>();
		ASSERT_NE(ethLayer, nullptr);
		ASSERT_NE(ip4Layer, nullptr);
		EXPECT_GE(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip4Layer->getDataLen());
		EXPECT_EQ(ip4Layer->getDataLen(), be16toh(ip4Layer->getIPv4Header()->totalLength));

		ethLayer = trailerIPv6Packet.getLayerOfType<EthLayer>();
		IPv6Layer* ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		ASSERT_NE(ethLayer, nullptr);
		ASSERT_NE(ip6Layer, nullptr);
		EXPECT_GE(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip6Layer->getDataLen());
		EXPECT_EQ(ip6Layer->getDataLen(), be16toh(ip6Layer->getIPv6Header()->payloadLength) + ip6Layer->getHeaderLen());

		// add layer before trailer
		auto newVlanLayer = new VlanLayer(123, true, 1, PCPP_ETHERTYPE_IPV6);
		ASSERT_TRUE(trailerIPv6Packet.insertLayer(ethLayer, newVlanLayer, true));
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 468);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// add layer just before trailer
		auto httpReq = new HttpRequestLayer(HttpRequestLayer::HttpGET, "/main.html", OneDotOne);
		httpReq->addEndOfHeader();
		TcpLayer* tcpLayer = trailerIPv4Packet.getLayerOfType<TcpLayer>();
		ASSERT_NE(tcpLayer, nullptr);
		trailerIPv4Packet.insertLayer(tcpLayer, httpReq, true);
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 87);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 67);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen(), 47);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen(), 27);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// add layer after trailer (result with an error)
		uint8_t payload[4] = { 0x1, 0x2, 0x3, 0x4 };
		std::unique_ptr<PayloadLayer> newPayloadLayer = std::make_unique<PayloadLayer>(payload, 4);
		Logger::getInstance().suppressLogs();
		ASSERT_FALSE(trailerIPv4Packet.addLayer(newPayloadLayer.get(), true));
		Logger::getInstance().enableLogs();

		// remove layer before trailer
		EXPECT_TRUE(trailerIPv4Packet.removeLayer(TCP));
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 67);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 47);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen(), 27);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// remove layer just before trailer
		EXPECT_TRUE(trailerIPv4Packet.removeLayer(HTTPRequest));
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 40);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 20);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// remove trailer
		ethLayer = trailerIPv6Packet2.getLayerOfType<EthLayer>();
		auto newVlanLayer2 = new VlanLayer(456, true, 1, PCPP_ETHERTYPE_IPV6);
		ASSERT_TRUE(trailerIPv6Packet2.insertLayer(ethLayer, newVlanLayer2, true));
		PacketTrailerLayer* packetTrailer = trailerIPv6Packet2.getLayerOfType<PacketTrailerLayer>();
		ASSERT_NE(packetTrailer, nullptr);
		ASSERT_TRUE(trailerIPv6Packet2.removeLayer(PacketTrailer));
		trailerIPv6Packet2.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<EthLayer>()->getDataLen(), 464);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<VlanLayer>()->getDataLen(), 450);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet2.getLayerOfType<DnsLayer>()->getDataLen(), 398);

		// remove all layers but the trailer
		ASSERT_TRUE(trailerIPv4Packet.removeLayer(Ethernet));
		trailerIPv4Packet.computeCalculateFields();
		ASSERT_TRUE(trailerIPv4Packet.removeLayer(IPv4));
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// rebuild packet starting from trailer
		auto newEthLayer =
		    new EthLayer(MacAddress("30:46:9a:23:fb:fa"), MacAddress("6c:f0:49:b2:de:6e"), PCPP_ETHERTYPE_IP);
		ASSERT_TRUE(trailerIPv4Packet.insertLayer(nullptr, newEthLayer, true));
		auto newIp4Layer = new IPv4Layer(IPv4Address("173.194.78.104"), IPv4Address("10.0.0.1"));
		newIp4Layer->getIPv4Header()->ipId = htobe16(40382);
		newIp4Layer->getIPv4Header()->timeToLive = 46;
		trailerIPv4Packet.insertLayer(newEthLayer, newIp4Layer, true);
		auto newTcpLayer = new TcpLayer(443, 55194);
		newTcpLayer->getTcpHeader()->ackNumber = htobe32(0x807df56c);
		newTcpLayer->getTcpHeader()->sequenceNumber = htobe32(0x46529f28);
		newTcpLayer->getTcpHeader()->ackFlag = 1;
		newTcpLayer->getTcpHeader()->windowSize = htobe16(344);
		trailerIPv4Packet.insertLayer(newIp4Layer, newTcpLayer, true);
		trailerIPv4Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen(), 60);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen(), 40);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen(), 20);
		EXPECT_EQ(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 6);

		// extend layer before trailer
		ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		IPv6RoutingHeader routingExt(4, 3, nullptr, 0);
		ip6Layer->addExtension<IPv6RoutingHeader>(routingExt);
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 476);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 462);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// extend layer just before trailer
		PPPoEDiscoveryLayer* pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
		ASSERT_NE(pppoeDiscovery, nullptr);
		// clang-format off
		ASSERT_FALSE(pppoeDiscovery->addTag(PPPoEDiscoveryLayer::PPPoETagBuilder(PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 0x42524153)).isNull());
		// clang-format on
		trailerPPPoEDPacket.computeCalculateFields();
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen(), 68);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen(), 26);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 28);

		// shorten layer before trailer
		ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
		ip6Layer->removeAllExtensions();
		trailerIPv6Packet.computeCalculateFields();
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen(), 468);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen(), 454);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen(), 446);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen(), 406);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen(), 398);
		EXPECT_EQ(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 4);

		// shorten layer just before trailer
		pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
		ASSERT_TRUE(pppoeDiscovery->removeAllTags());
		trailerPPPoEDPacket.computeCalculateFields();
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen(), 48);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen(), 6);
		EXPECT_EQ(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen(), 28);
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ResizeLayer)
	{
		uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
		PayloadLayer payloadLayer(payload, 10);

		// Creating a packet
		Packet packet(1500);
		ASSERT_TRUE(packet.addLayer(&payloadLayer));

		// Starting Resize testing
		ASSERT_EQ(packet.getRawPacket()->getRawDataLen(), 10);  // Size of packet before resizing is not correct

		//
		// test shortening of packet and layer
		//
		uint8_t payload2[] = { 0x05, 0x04, 0x03, 0x02, 0x01 };
		size_t payload2_size = 5;
		payloadLayer.setPayload(payload2, payload2_size);

		// check that resizing worked in terms of data length
		ASSERT_EQ(packet.getRawPacket()->getRawDataLen(),
		          (int)payload2_size);  // Size of packet after first resizing (shortening) is not correct

		// confirm that data has been correctly written to raw packet
		const uint8_t* rawData =
		    packet.getRawPacket()->getRawData() + (packet.getRawPacket()->getRawDataLen() - payload2_size);
		EXPECT_EQ(rawData[0], 0x05);  // Setting payload to new payload has failed.
		EXPECT_EQ(rawData[1], 0x04);
		EXPECT_EQ(rawData[2], 0x03);
		EXPECT_EQ(rawData[3], 0x02);
		EXPECT_EQ(rawData[4], 0x01);

		//
		// test extension of packet and layer
		//
		uint8_t payload3[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
		size_t payload3_size = 8;
		payloadLayer.setPayload(payload3, payload3_size);

		// check that resizing worked in terms of data length
		ASSERT_EQ(packet.getRawPacket()->getRawDataLen(),
		          (int)payload3_size);  // Size of packet after second resizing (extension) is not correct

		// confirm that data has been correctly written to raw packet
		const uint8_t* rawData2 =
		    packet.getRawPacket()->getRawData() + (packet.getRawPacket()->getRawDataLen() - payload3_size);
		EXPECT_EQ(rawData2[0], 0xDE);  // Setting payload to new payload has failed.
		EXPECT_EQ(rawData2[1], 0xAD);
		EXPECT_EQ(rawData2[2], 0xBE);
		EXPECT_EQ(rawData2[3], 0xEF);
		EXPECT_EQ(rawData2[4], 0xDE);
		EXPECT_EQ(rawData2[5], 0xAD);
		EXPECT_EQ(rawData2[6], 0xBE);
		EXPECT_EQ(rawData2[7], 0xEF);
	}

	TEST(PacketTest, PrintPacketAndLayers)
	{
		timeval time;
		time.tv_sec = 1634026009;
		time.tv_usec = 0;

		// convert the timestamp to a printable format
		time_t nowtime = time.tv_sec;
		struct tm* nowtm = nullptr;
#if __cplusplus > 199711L && !defined(_WIN32)
		// localtime_r is a thread-safe versions of localtime,
		// but they're defined only in newer compilers (>= C++0x).
		// on Windows localtime is already thread-safe so there is not need
		// to use localtime_r
		struct tm nowtm_r;
		nowtm = localtime_r(&nowtime, &nowtm_r);
#else
		// on Window compilers localtime is already thread safe.
		// in old compilers (< C++0x) localtime_r was not defined so we have to fall back to localtime
		nowtm = localtime(&nowtime);
#endif

		char tmbuf[64];
		strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

		auto packetFactory = test::PacketFactory().withTime(time);

		auto rawPacket1 = test::createPacketFromHexResource("PacketExamples/MplsPackets1.dat", packetFactory);
		Packet packet(rawPacket1.get());

		std::string expectedPacketHeaderString =
		    "Packet length: 361 [Bytes], Arrival time: " + std::string(tmbuf) + ".000000000";
		std::vector<std::string> expectedLayerStrings;
		expectedLayerStrings.push_back("Ethernet II Layer, Src: 50:81:89:f9:d5:7b, Dst: 28:c2:ce:ba:97:e8");
		expectedLayerStrings.push_back("VLAN Layer, Priority: 0, Vlan ID: 215, CFI: 0");
		expectedLayerStrings.push_back("VLAN Layer, Priority: 0, Vlan ID: 11, CFI: 0");
		expectedLayerStrings.push_back("MPLS Layer, Label: 16000, Exp: 0, TTL: 126, Bottom of stack: true");
		expectedLayerStrings.push_back("IPv4 Layer, Src: 2.3.4.6, Dst: 12.13.14.15");
		expectedLayerStrings.push_back("TCP Layer, [ACK], Src port: 20636, Dst port: 80");
		expectedLayerStrings.push_back("HTTP request, GET /i/?tid=199&hash=8ktxrl&subid=0 HTTP/1.1");

		// test print layers
		std::vector<std::string>::iterator iter = expectedLayerStrings.begin();
		for (Layer* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer())
		{
			ASSERT_EQ(layer->toString(), *iter);
			std::ostringstream layerStream;
			layerStream << *layer;
			ASSERT_EQ(layerStream.str(), *iter);
			++iter;
		}
		ASSERT_EQ(iter, expectedLayerStrings.end());

		// test print packet
		std::ostringstream expectedStream;
		expectedStream << expectedPacketHeaderString << std::endl;
		for (const auto& it : expectedLayerStrings)
		{
			expectedStream << it << std::endl;
		}

		std::ostringstream packetStream;
		packetStream << packet;
		ASSERT_EQ(packetStream.str(), expectedStream.str());
		ASSERT_EQ(packet.toString(), expectedStream.str());

		expectedLayerStrings.insert(expectedLayerStrings.begin(), expectedPacketHeaderString);
		std::vector<std::string> packetAsStringList;
		packet.toStringList(packetAsStringList);
		ASSERT_EQ(packetAsStringList, expectedLayerStrings);
	}

	// TODO: Should this be in PacketTest fixture?
	TEST(PacketTest, ProtocolFamilyMembership)
	{
		auto rawPacket = test::createPacketFromHexResource("PacketExamples/TwoHttpRequests1.dat");
		Packet packet(rawPacket.get());

		auto ipV4Layer = packet.getLayerOfType<IPv4Layer>();
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(IP));
		EXPECT_TRUE(ipV4Layer->isMemberOfProtocolFamily(IPv4));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(IPv6));
		EXPECT_FALSE(ipV4Layer->isMemberOfProtocolFamily(HTTP));

		auto httpLayer = packet.getLayerOfType<HttpRequestLayer>();
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(HTTP));
		EXPECT_TRUE(httpLayer->isMemberOfProtocolFamily(HTTPRequest));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(HTTPResponse));
		EXPECT_FALSE(httpLayer->isMemberOfProtocolFamily(IP));
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
