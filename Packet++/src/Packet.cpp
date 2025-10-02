#define LOG_MODULE PacketLogModulePacket

#include "Packet.h"
#include "EthLayer.h"
#include "EthDot3Layer.h"
#include "SllLayer.h"
#include "Sll2Layer.h"
#include "NflogLayer.h"
#include "NullLoopbackLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "CiscoHdlcLayer.h"
#include "PayloadLayer.h"
#include "PacketTrailerLayer.h"
#include "Logger.h"
#include <numeric>
#include <sstream>
#include <memory>
#ifdef _MSC_VER
#	include <time.h>
#	include "SystemUtils.h"
#endif

namespace pcpp
{
	namespace
	{
		Layer* createLinkLayer(RawPacket& rawPacket, Packet* packet)
		{
			// Stripping const because getRawData always returns const ptr, and layers require non-const ptr.
			auto rawData = const_cast<uint8_t*>(rawPacket.getRawData());
			auto rawDataLen = static_cast<size_t>(rawPacket.getRawDataLen());

			switch (rawPacket.getLinkLayerType())
			{
			case LinkLayerType::LINKTYPE_ETHERNET:
			{
				if (EthLayer::isDataValid(rawData, rawDataLen))
				{
					return new EthLayer(rawData, rawDataLen, packet);
				}
				else if (EthDot3Layer::isDataValid(rawData, rawDataLen))
				{
					return new EthDot3Layer(rawData, rawDataLen, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_LINUX_SLL:
			{
				return new SllLayer(rawData, rawDataLen, packet);
			}
			case LinkLayerType::LINKTYPE_LINUX_SLL2:
			{
				if (Sll2Layer::isDataValid(rawData, rawDataLen))
				{
					return new Sll2Layer(rawData, rawDataLen, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_NULL:
			{
				// Validate that the length is enough for Null/Loopback
				if (rawDataLen >= sizeof(uint32_t))
				{
					return new NullLoopbackLayer(rawData, rawDataLen, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_RAW:
			case LinkLayerType::LINKTYPE_DLT_RAW1:
			case LinkLayerType::LINKTYPE_DLT_RAW2:
			{
				uint8_t ipVer = rawData[0] & 0xf0;
				if (ipVer == 0x40 && IPv4Layer::isDataValid(rawData, rawDataLen))
				{
					return new IPv4Layer(rawData, rawDataLen, nullptr, packet);
				}
				else if (ipVer == 0x60 && IPv6Layer::isDataValid(rawData, rawDataLen))
				{
					return new IPv6Layer(rawData, rawDataLen, nullptr, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_IPV4:
			{
				if (IPv4Layer::isDataValid(rawData, rawDataLen))
				{
					return new IPv4Layer(rawData, rawDataLen, nullptr, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_IPV6:
			{
				if (IPv6Layer::isDataValid(rawData, rawDataLen))
				{
					return new IPv6Layer(rawData, rawDataLen, nullptr, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_NFLOG:
			{
				if (NflogLayer::isDataValid(rawData, rawDataLen))
				{
					return new NflogLayer(rawData, rawDataLen, packet);
				}
				break;
			}
			case LinkLayerType::LINKTYPE_C_HDLC:
			{
				if (CiscoHdlcLayer::isDataValid(rawData, rawDataLen))
				{
					return new CiscoHdlcLayer(rawData, rawDataLen, packet);
				}
				break;
			}
			default:
				// Other link layer types don't have layers, so we create a generic payload layer.
				break;
			}

			return new PayloadLayer(rawData, rawDataLen, nullptr, packet);
		}
	}  // namespace

	Packet::Packet(size_t maxPacketLen, LinkLayerType linkType)
	    : m_RawPacket(nullptr), m_FirstLayer(nullptr), m_LastLayer(nullptr), m_MaxPacketLen(maxPacketLen),
	      m_FreeRawPacket(true), m_CanReallocateData(true)
	{
		timeval time;
		gettimeofday(&time, nullptr);
		uint8_t* data = new uint8_t[maxPacketLen];
		memset(data, 0, maxPacketLen);
		m_RawPacket = new RawPacket(data, 0, time, true, linkType);
	}

	Packet::Packet(uint8_t* buffer, size_t bufferSize, LinkLayerType linkType)
	    : m_RawPacket(nullptr), m_FirstLayer(nullptr), m_LastLayer(nullptr), m_MaxPacketLen(bufferSize),
	      m_FreeRawPacket(true), m_CanReallocateData(false)
	{
		timeval time;
		gettimeofday(&time, nullptr);
		memset(buffer, 0, bufferSize);
		m_RawPacket = new RawPacket(buffer, 0, time, false, linkType);
	}

	void Packet::setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolTypeFamily parseUntil,
	                          OsiModelLayer parseUntilLayer)
	{
		destructPacketData();

		m_FirstLayer = nullptr;
		m_LastLayer = nullptr;
		m_MaxPacketLen = rawPacket->getRawDataLen();
		m_FreeRawPacket = freeRawPacket;
		m_RawPacket = rawPacket;
		m_CanReallocateData = true;
		if (m_RawPacket == nullptr)
			return;

		LinkLayerType linkType = m_RawPacket->getLinkLayerType();

		m_FirstLayer = createLinkLayer(*m_RawPacket, this);

		// As the stop conditions are inclusive, the parse must go one layer further and then roll back if needed
		bool rollbackLastLayer = false;
		bool foundTargetProtocol = false;
		for (auto* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			// Mark the current layer as allocated in the packet
			curLayer->m_IsAllocatedInPacket = true;
			m_LastLayer = curLayer;  // Update last layer to current layer

			// If the current layer is of a higher OSI layer than the target, stop parsing
			if (curLayer->getOsiModelLayer() > parseUntilLayer)
			{
				rollbackLastLayer = true;
				break;
			}

			// If we are searching for a specific layer protocol, record when we find at least one target.
			const bool matchesTarget = curLayer->isMemberOfProtocolFamily(parseUntil);
			if (parseUntil != UnknownProtocol && matchesTarget)
			{
				foundTargetProtocol = true;
			}

			// If we have found the target protocol already, we are parsing until we find a different protocol
			if (foundTargetProtocol && !matchesTarget)
			{
				rollbackLastLayer = true;
				break;
			}

			// Parse the next layer. This will update the next layer pointer of the current layer.
			curLayer->parseNextLayer();
		}

		// Roll back one layer, if parsing with search condition as the conditions are inclusive.
		// Don't delete the first layer. If already past the target layer, treat the same as if the layer was found.
		if (rollbackLastLayer && m_LastLayer != m_FirstLayer)
		{
			m_LastLayer = m_LastLayer->getPrevLayer();
			delete m_LastLayer->m_NextLayer;
			m_LastLayer->m_NextLayer = nullptr;
		}

		// If there is data left in the raw packet that doesn't belong to any layer, create a PacketTrailerLayer
		if (m_LastLayer != nullptr && parseUntil == UnknownProtocol && parseUntilLayer == OsiModelLayerUnknown)
		{
			// find if there is data left in the raw packet that doesn't belong to any layer. In that case it's probably
			// a packet trailer. create a PacketTrailerLayer layer and add it at the end of the packet
			int trailerLen = (int)((m_RawPacket->getRawData() + m_RawPacket->getRawDataLen()) -
			                       (m_LastLayer->getData() + m_LastLayer->getDataLen()));
			if (trailerLen > 0)
			{
				PacketTrailerLayer* trailerLayer =
				    new PacketTrailerLayer(static_cast<uint8_t*>(m_LastLayer->getData() + m_LastLayer->getDataLen()),
				                           trailerLen, m_LastLayer, this);

				trailerLayer->m_IsAllocatedInPacket = true;
				m_LastLayer->setNextLayer(trailerLayer);
				m_LastLayer = trailerLayer;
			}
		}
	}

	Packet::Packet(RawPacket* rawPacket, bool freeRawPacket, ProtocolType parseUntil, OsiModelLayer parseUntilLayer)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, freeRawPacket, parseUntil, parseUntilLayer);
	}

	Packet::Packet(RawPacket* rawPacket, ProtocolType parseUntil)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		auto parseUntilFamily = static_cast<ProtocolTypeFamily>(parseUntil);
		setRawPacket(rawPacket, false, parseUntilFamily, OsiModelLayerUnknown);
	}

	Packet::Packet(RawPacket* rawPacket, ProtocolTypeFamily parseUntilFamily)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, false, parseUntilFamily, OsiModelLayerUnknown);
	}

	Packet::Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer)
	{
		m_FreeRawPacket = false;
		m_RawPacket = nullptr;
		m_FirstLayer = nullptr;
		setRawPacket(rawPacket, false, UnknownProtocol, parseUntilLayer);
	}

	void Packet::destructPacketData()
	{
		Layer* curLayer = m_FirstLayer;
		while (curLayer != nullptr)
		{
			Layer* nextLayer = curLayer->getNextLayer();
			if (curLayer->m_IsAllocatedInPacket)
				delete curLayer;
			curLayer = nextLayer;
		}

		if (m_RawPacket != nullptr && m_FreeRawPacket)
		{
			delete m_RawPacket;
		}
	}

	Packet& Packet::operator=(const Packet& other)
	{
		destructPacketData();

		copyDataFrom(other);

		return *this;
	}

	void Packet::copyDataFrom(const Packet& other)
	{
		m_RawPacket = new RawPacket(*(other.m_RawPacket));
		m_FreeRawPacket = true;
		m_MaxPacketLen = other.m_MaxPacketLen;
		m_FirstLayer = createLinkLayer(*m_RawPacket, this);
		m_LastLayer = m_FirstLayer;
		m_CanReallocateData = true;
		Layer* curLayer = m_FirstLayer;
		while (curLayer != nullptr)
		{
			curLayer->parseNextLayer();
			curLayer->m_IsAllocatedInPacket = true;
			curLayer = curLayer->getNextLayer();
			if (curLayer != nullptr)
				m_LastLayer = curLayer;
		}
	}

	void Packet::reallocateRawData(size_t newSize)
	{
		PCPP_LOG_DEBUG("Allocating packet to new size: " << newSize);

		// allocate a new array with size newSize
		m_MaxPacketLen = newSize;

		// set the new array to RawPacket
		if (!m_RawPacket->reallocateData(m_MaxPacketLen))
		{
			PCPP_LOG_ERROR("Couldn't reallocate data of raw packet to " << m_MaxPacketLen << " bytes");
			return;
		}

		// set all data pointers in layers to the new array address
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			PCPP_LOG_DEBUG("Setting new data pointer to layer '" << typeid(curLayer).name() << "'");
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);
			dataPtr += curLayer->getHeaderLen();
		}
	}

	bool Packet::insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket)
	{
		if (newLayer == nullptr)
		{
			PCPP_LOG_ERROR("Layer to add is nullptr");
			return false;
		}

		if (newLayer->isAllocatedToPacket())
		{
			PCPP_LOG_ERROR("Layer is already allocated to another packet. Cannot use layer in more than one packet");
			return false;
		}

		if (prevLayer != nullptr && prevLayer->getProtocol() == PacketTrailer)
		{
			PCPP_LOG_ERROR("Cannot insert layer after packet trailer");
			return false;
		}

		size_t newLayerHeaderLen = newLayer->getHeaderLen();
		if (m_RawPacket->getRawDataLen() + newLayerHeaderLen > m_MaxPacketLen)
		{
			if (!m_CanReallocateData)
			{
				PCPP_LOG_ERROR("With the new layer the packet will exceed the size of the pre-allocated buffer: "
				               << m_MaxPacketLen << " bytes");
				return false;
			}
			// reallocate to maximum value of: twice the max size of the packet or max size + new required length
			if (m_RawPacket->getRawDataLen() + newLayerHeaderLen > m_MaxPacketLen * 2)
				reallocateRawData(m_RawPacket->getRawDataLen() + newLayerHeaderLen + m_MaxPacketLen);
			else
				reallocateRawData(m_MaxPacketLen * 2);
		}

		// insert layer data to raw packet
		int indexToInsertData = 0;
		if (prevLayer != nullptr)
			indexToInsertData = prevLayer->m_Data + prevLayer->getHeaderLen() - m_RawPacket->getRawData();
		m_RawPacket->insertData(indexToInsertData, newLayer->m_Data, newLayerHeaderLen);

		// delete previous layer data
		delete[] newLayer->m_Data;

		// add layer to layers linked list
		if (prevLayer != nullptr)
		{
			newLayer->setNextLayer(prevLayer->getNextLayer());
			newLayer->setPrevLayer(prevLayer);
			prevLayer->setNextLayer(newLayer);
		}
		else  // prevLayer == nullptr
		{
			newLayer->setNextLayer(m_FirstLayer);
			if (m_FirstLayer != nullptr)
				m_FirstLayer->setPrevLayer(newLayer);
			m_FirstLayer = newLayer;
		}

		if (newLayer->getNextLayer() == nullptr)
			m_LastLayer = newLayer;
		else
			newLayer->getNextLayer()->setPrevLayer(newLayer);

		// assign layer with this packet only
		newLayer->m_Packet = this;

		// Set flag to indicate if new layer is allocated to packet.
		if (ownInPacket)
			newLayer->m_IsAllocatedInPacket = true;

		// re-calculate all layers data ptr and data length

		// first, get ptr and data length of the raw packet
		const uint8_t* dataPtr = m_RawPacket->getRawData();
		size_t dataLen = static_cast<size_t>(m_RawPacket->getRawDataLen());

		// if a packet trailer exists, get its length
		size_t packetTrailerLen = 0;
		if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
			packetTrailerLen = m_LastLayer->getDataLen();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			// set data ptr to layer
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
			// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the
			// whole data, including the packet trailer. If this layer is L3-7, exclude the packet trailer from its data
			// length
			if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
				curLayer->m_DataLen = dataLen;
			else
				curLayer->m_DataLen = dataLen - packetTrailerLen;

			// advance data ptr and data length
			dataPtr += curLayer->getHeaderLen();
			dataLen -= curLayer->getHeaderLen();
		}

		return true;
	}

	bool Packet::removeLayer(ProtocolType layerType, int index)
	{
		Layer* layerToRemove = getLayerOfType(layerType, index);

		if (layerToRemove != nullptr)
		{
			return removeLayer(layerToRemove, true);
		}
		else
		{
			PCPP_LOG_ERROR("Layer of the requested type was not found in packet");
			return false;
		}
	}

	bool Packet::removeFirstLayer()
	{
		Layer* firstLayer = getFirstLayer();
		if (firstLayer == nullptr)
		{
			PCPP_LOG_ERROR("Packet has no layers");
			return false;
		}

		return removeLayer(firstLayer, true);
	}

	bool Packet::removeLastLayer()
	{
		Layer* lastLayer = getLastLayer();
		if (lastLayer == nullptr)
		{
			PCPP_LOG_ERROR("Packet has no layers");
			return false;
		}

		return removeLayer(lastLayer, true);
	}

	bool Packet::removeAllLayersAfter(Layer* layer)
	{
		Layer* curLayer = layer->getNextLayer();
		while (curLayer != nullptr)
		{
			Layer* tempLayer = curLayer->getNextLayer();
			if (!removeLayer(curLayer, true))
				return false;
			curLayer = tempLayer;
		}

		return true;
	}

	Layer* Packet::detachLayer(ProtocolType layerType, int index)
	{
		Layer* layerToDetach = getLayerOfType(layerType, index);

		if (layerToDetach != nullptr)
		{
			if (removeLayer(layerToDetach, false))
				return layerToDetach;
			else
				return nullptr;
		}
		else
		{
			PCPP_LOG_ERROR("Layer of the requested type was not found in packet");
			return nullptr;
		}
	}

	bool Packet::removeLayer(Layer* layer, bool tryToDelete)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to a packet
		if (!layer->isAllocatedToPacket())
		{
			PCPP_LOG_ERROR("Layer isn't allocated to any packet");
			return false;
		}

		// verify layer is allocated to *this* packet
		Layer* curLayer = layer;
		while (curLayer->m_PrevLayer != nullptr)
			curLayer = curLayer->m_PrevLayer;
		if (curLayer != m_FirstLayer)
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		// before removing the layer's data, copy it so it can be later assigned as the removed layer's data
		size_t headerLen = layer->getHeaderLen();
		size_t layerOldDataSize = headerLen;
		auto layerOldData = std::make_unique<uint8_t[]>(layerOldDataSize);
		memcpy(layerOldData.get(), layer->m_Data, layerOldDataSize);

		// remove data from raw packet
		size_t numOfBytesToRemove = headerLen;
		int indexOfDataToRemove = layer->m_Data - m_RawPacket->getRawData();
		if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToRemove))
		{
			PCPP_LOG_ERROR("Couldn't remove data from packet");
			return false;
		}

		// remove layer from layers linked list
		if (layer->m_PrevLayer != nullptr)
			layer->m_PrevLayer->setNextLayer(layer->m_NextLayer);
		if (layer->m_NextLayer != nullptr)
			layer->m_NextLayer->setPrevLayer(layer->m_PrevLayer);

		// take care of head and tail ptrs
		if (m_FirstLayer == layer)
			m_FirstLayer = layer->m_NextLayer;
		if (m_LastLayer == layer)
			m_LastLayer = layer->m_PrevLayer;
		layer->setNextLayer(nullptr);
		layer->setPrevLayer(nullptr);

		// get packet trailer len if exists
		size_t packetTrailerLen = 0;
		if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
			packetTrailerLen = m_LastLayer->getDataLen();

		// re-calculate all layers data ptr and data length

		// first, get ptr and data length of the raw packet
		const uint8_t* dataPtr = m_RawPacket->getRawData();
		size_t dataLen = static_cast<size_t>(m_RawPacket->getRawDataLen());

		curLayer = m_FirstLayer;

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each one
		while (curLayer != nullptr)
		{
			// set data ptr to layer
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// there is an assumption here that the packet trailer, if exists, corresponds to the L2 (data link) layers.
			// so if there is a packet trailer and this layer is L2 (data link), set its data length to contain the
			// whole data, including the packet trailer. If this layer is L3-7, exclude the packet trailer from its data
			// length
			if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
				curLayer->m_DataLen = dataLen;
			else
				curLayer->m_DataLen = dataLen - packetTrailerLen;

			// advance data ptr and data length
			dataPtr += curLayer->getHeaderLen();
			dataLen -= curLayer->getHeaderLen();

			// move to next layer
			curLayer = curLayer->getNextLayer();
		}

		// if layer was allocated by this packet and tryToDelete flag is set, delete it
		if (tryToDelete && layer->m_IsAllocatedInPacket)
		{
			delete layer;
		}
		// if layer was not allocated by this packet or the tryToDelete is not set, detach it from the packet so it can
		// be reused
		else
		{
			layer->m_Packet = nullptr;
			layer->m_Data = layerOldData.release();
			layer->m_DataLen = layerOldDataSize;
		}

		return true;
	}

	Layer* Packet::getLayerOfType(ProtocolType layerType, int index) const
	{
		int curIndex = 0;
		for (Layer* curLayer = getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			if (curLayer->getProtocol() != layerType)
				continue;

			if (curIndex == index)
				return curLayer;

			curIndex++;
		}

		return nullptr;
	}

	bool Packet::isPacketOfType(ProtocolType protocolType) const
	{
		for (Layer* curLayer = getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			if (curLayer->getProtocol() == protocolType)
			{
				return true;
			}
		}

		return false;
	}

	bool Packet::isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const
	{
		Layer* curLayer = getFirstLayer();
		while (curLayer != nullptr)
		{
			if (curLayer->isMemberOfProtocolFamily(protocolTypeFamily))
			{
				return true;
			}
			curLayer = curLayer->getNextLayer();
		}

		return false;
	}

	bool Packet::extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to this packet
		if (!(layer->m_Packet == this))
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen)
		{
			if (!m_CanReallocateData)
			{
				PCPP_LOG_ERROR(
				    "With the layer extended size the packet will exceed the size of the pre-allocated buffer: "
				    << m_MaxPacketLen << " bytes");
				return false;
			}
			// reallocate to maximum value of: twice the max size of the packet or max size + new required length
			if (m_RawPacket->getRawDataLen() + numOfBytesToExtend > m_MaxPacketLen * 2)
				reallocateRawData(m_RawPacket->getRawDataLen() + numOfBytesToExtend + m_MaxPacketLen);
			else
				reallocateRawData(m_MaxPacketLen * 2);
		}

		// insert layer data to raw packet
		int indexToInsertData = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
		// passing nullptr to insertData will move the data by numOfBytesToExtend
		// no new data has to be created for this insertion which saves at least little time
		// this move operation occurs on already allocated memory, which is backed by the reallocation if's provided
		// above if offsetInLayer == layer->getHeaderLen() insertData will not move any data but only increase the
		// packet size by numOfBytesToExtend
		m_RawPacket->insertData(indexToInsertData, nullptr, numOfBytesToExtend);

		// re-calculate all layers data ptr and data length
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
		bool passedExtendedLayer = false;
		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			// set the data ptr
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// set a flag if arrived to the layer being extended
			if (curLayer->getPrevLayer() == layer)
				passedExtendedLayer = true;

			// change the data length only for layers who come before the extended layer. For layers who come after,
			// data length isn't changed
			if (!passedExtendedLayer)
				curLayer->m_DataLen += numOfBytesToExtend;

			// assuming header length of the layer that requested to be extended hasn't been enlarged yet
			size_t headerLen = curLayer->getHeaderLen() + (curLayer == layer ? numOfBytesToExtend : 0);
			dataPtr += headerLen;
		}

		return true;
	}

	bool Packet::shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten)
	{
		if (layer == nullptr)
		{
			PCPP_LOG_ERROR("Layer is nullptr");
			return false;
		}

		// verify layer is allocated to this packet
		if (!(layer->m_Packet == this))
		{
			PCPP_LOG_ERROR("Layer isn't allocated to this packet");
			return false;
		}

		// remove data from raw packet
		int indexOfDataToRemove = layer->m_Data + offsetInLayer - m_RawPacket->getRawData();
		if (!m_RawPacket->removeData(indexOfDataToRemove, numOfBytesToShorten))
		{
			PCPP_LOG_ERROR("Couldn't remove data from packet");
			return false;
		}

		// re-calculate all layers data ptr and data length
		const uint8_t* dataPtr = m_RawPacket->getRawData();

		// go over all layers from the first layer to the last layer and set the data ptr and data length for each layer
		Layer* curLayer = m_FirstLayer;
		bool passedExtendedLayer = false;
		while (curLayer != nullptr)
		{
			// set the data ptr
			curLayer->m_Data = const_cast<uint8_t*>(dataPtr);

			// set a flag if arrived to the layer being shortened
			if (curLayer->getPrevLayer() == layer)
				passedExtendedLayer = true;

			// change the data length only for layers who come before the shortened layer. For layers who come after,
			// data length isn't changed
			if (!passedExtendedLayer)
				curLayer->m_DataLen -= numOfBytesToShorten;

			// assuming header length of the layer that requested to be extended hasn't been enlarged yet
			size_t headerLen = curLayer->getHeaderLen() - (curLayer == layer ? numOfBytesToShorten : 0);
			dataPtr += headerLen;
			curLayer = curLayer->getNextLayer();
		}

		return true;
	}

	void Packet::computeCalculateFields()
	{
		// calculated fields should be calculated from top layer to bottom layer
		for (Layer* curLayer = m_LastLayer; curLayer != nullptr; curLayer = curLayer->getPrevLayer())
		{
			curLayer->computeCalculateFields();
		}
	}

	std::string Packet::printPacketInfo(bool timeAsLocalTime) const
	{
		std::ostringstream dataLenStream;
		dataLenStream << m_RawPacket->getRawDataLen();

		// convert raw packet timestamp to printable format
		timespec timestamp = m_RawPacket->getPacketTimeStamp();
		time_t nowtime = timestamp.tv_sec;
		struct tm* nowtm = nullptr;
#if __cplusplus > 199711L && !defined(_WIN32)
		// localtime_r and gmtime_r are thread-safe versions of localtime and gmtime,
		// but they're defined only in newer compilers (>= C++0x).
		// on Windows localtime and gmtime are already thread-safe so there is not need
		// to use localtime_r and gmtime_r
		struct tm nowtm_r;
		if (timeAsLocalTime)
			nowtm = localtime_r(&nowtime, &nowtm_r);
		else
			nowtm = gmtime_r(&nowtime, &nowtm_r);

		if (nowtm != nullptr)
			nowtm = &nowtm_r;
#else
		// on Window compilers localtime and gmtime are already thread safe.
		// in old compilers (< C++0x) gmtime_r and localtime_r were not defined so we have to fall back to localtime and
		// gmtime
		if (timeAsLocalTime)
			nowtm = localtime(&nowtime);
		else
			nowtm = gmtime(&nowtime);
#endif

		char buf[128];
		if (nowtm != nullptr)
		{
			char tmbuf[64];
			strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
			snprintf(buf, sizeof(buf), "%s.%09lu", tmbuf, (unsigned long)timestamp.tv_nsec);
		}
		else
			snprintf(buf, sizeof(buf), "0000-00-00 00:00:00.000000000");

		return "Packet length: " + dataLenStream.str() + " [Bytes], Arrival time: " + std::string(buf);
	}

	std::string Packet::toString(bool timeAsLocalTime) const
	{
		std::vector<std::string> stringList;
		toStringList(stringList, timeAsLocalTime);
		return std::accumulate(stringList.begin(), stringList.end(), std::string(),
		                       [](std::string a, const std::string& b) { return std::move(a) + b + '\n'; });
	}

	void Packet::toStringList(std::vector<std::string>& result, bool timeAsLocalTime) const
	{
		result.clear();
		result.push_back(printPacketInfo(timeAsLocalTime));

		for (Layer* curLayer = m_FirstLayer; curLayer != nullptr; curLayer = curLayer->getNextLayer())
		{
			result.push_back(curLayer->toString());
		}
	}

	namespace experimental
	{
		MemoryArena::MemoryArena(MemoryArena&& other) noexcept
		    : m_BlockSize(other.m_BlockSize), m_FirstBlock(other.m_FirstBlock), m_AllocBlock(other.m_AllocBlock)
		{
			// Block size is not changed in the moved-from object
			// This is to allow the moved from object to be reused
			other.m_FirstBlock = nullptr;
			other.m_AllocBlock = nullptr;
		}

		MemoryArena& MemoryArena::operator=(MemoryArena&& other) noexcept
		{
			if (this == &other)
				return *this;

			reset(0);
			m_BlockSize = other.m_BlockSize;
			m_FirstBlock = other.m_FirstBlock;
			m_AllocBlock = other.m_AllocBlock;

			// Block size is not changed in the moved-from object
			// This is to allow the moved from object to be reused
			other.m_FirstBlock = nullptr;
			other.m_AllocBlock = nullptr;
			return *this;
		}

		bool MemoryArena::isAllocated() const
		{
			return m_FirstBlock != nullptr;
		}

		bool MemoryArena::isEmpty() const
		{
			return m_FirstBlock == nullptr || (m_FirstBlock == m_AllocBlock && m_FirstBlock->usedBytes == 0);
		}

		void* MemoryArena::allocate(size_t bytes, size_t alignment)
		{
			if (bytes == 0)
			{
				// 0 bytes allocation requirements are implementation defined. We choose to return nullptr.
				return nullptr;
			}

			if (m_AllocBlock == nullptr)
			{
				// No blocks exist yet, create the first one
				reserve(1);
			}

			// Base ptr is the start of the block, used to update usedBytes if allocation succeeds
			// Alligned ptr is the pointer we will try to align, it starts as the first unused byte in the block
			void* basePtr = m_AllocBlock->getBlockData();
			void* alignedPtr = m_AllocBlock->getUnusedData();
			size_t space = m_AllocBlock->getUnusedBytes(m_BlockSize);

			// align modifies alignedPtr and space to reflect the alignment, if possible
			// space is the number of bytes available after alignment
			if (std::align(alignment, bytes, alignedPtr, space))
			{
				// We have enough space in this block, update usedBytes and return the aligned pointer
				size_t usedBytes = static_cast<uint8_t*>(alignedPtr) - static_cast<uint8_t*>(basePtr) + bytes;
				m_AllocBlock->usedBytes = usedBytes;
				return alignedPtr;
			}
			else if (m_AllocBlock->usedBytes == 0)
			{
				// There is no point in creating a new block if the alignment failed on an empty one.
				throw std::bad_alloc();
			}
			else
			{
				// The alignment failed on a non-empty block. Allocate a new one and attempt again.
				// This essentially wastes all the space left in the previous block, but it is done to keep the
				// allocation mechanism fast. (no list traversal to find a block)

				// Can't align in this block, try the next one
				if (m_AllocBlock->next == nullptr)
				{
					// No next block, create one
					m_AllocBlock = createBlock(m_AllocBlock);
				}
				else
				{
					// Move to the next block
					m_AllocBlock = m_AllocBlock->next;
				}

				// Try to allocate in the next block
				basePtr = m_AllocBlock->getBlockData();
				alignedPtr = m_AllocBlock->getUnusedData();
				space = m_AllocBlock->getUnusedBytes(m_BlockSize);

				if (std::align(alignment, bytes, alignedPtr, space))
				{
					// We have enough space in this block, update usedBytes and return the aligned pointer
					size_t usedBytes = static_cast<uint8_t*>(alignedPtr) - static_cast<uint8_t*>(basePtr) + bytes;
					m_AllocBlock->usedBytes = usedBytes;
					return alignedPtr;
				}
				else
				{
					// Can't align in this block either, allocation fails
					throw std::bad_alloc();
				}
			}
		}

		void MemoryArena::reserve(size_t numBlocks)
		{
			size_t reservedBlocks = 0;
			BlockHeader* block = m_FirstBlock;

			while (reservedBlocks < numBlocks && block != nullptr)
			{
				reservedBlocks++;
				block = block->next;
			}

			// Optimization: Allocate all the blocks in a single memory chunk?
			// But then we can't free individual blocks in reset()...
			// Possibly by adding a flag to the block header?
			while (reservedBlocks < numBlocks)
			{
				// Allocate additional blocks
				BlockHeader* newBlock = createBlock(block);
				reservedBlocks++;

				if (m_FirstBlock == nullptr)
				{
					// This is the first block, set both pointers
					m_FirstBlock = newBlock;
					m_AllocBlock = newBlock;
				}

				// Advances to the next block.
				block = newBlock;
			}
		}

		void MemoryArena::clear()
		{
			// Don't free the blocks, just reset their used bytes counter
			for (BlockHeader* block = m_FirstBlock; block != nullptr; block = block->next)
			{
				block->usedBytes = 0;
			}
		}

		void MemoryArena::reset(size_t keepBlocks)
		{
			if (m_FirstBlock == nullptr)
			{
				return;
			}

			// For the first 'keepBlocks' blocks, reset their used bytes counter
			// For the rest of the blocks, free them
			BlockHeader* prevBlock = nullptr;
			BlockHeader* block = m_FirstBlock;
			for (size_t i = 0; i < keepBlocks && block != nullptr; i++)
			{
				block->usedBytes = 0;
				prevBlock = block;
				block = block->next;
			}

			if (prevBlock != nullptr)
			{
				prevBlock->next = nullptr;    // Detach the blocks to free from the rest of the list
				m_AllocBlock = m_FirstBlock;  // Reset allocation pointer to the first block
			}
			else
			{
				// We are supposed to free all blocks
				m_AllocBlock = nullptr;
				m_FirstBlock = nullptr;
			}

			// Block now points to the first block to free
			while (block != nullptr)
			{
				BlockHeader* nextBlock = block->next;
				freeBlock(block);
				block = nextBlock;
			}
		}

		size_t MemoryArena::getNumBlocks() const
		{
			size_t count = 0;
			for (BlockHeader const* block = m_FirstBlock; block != nullptr; block = block->next)
			{
				count++;
			}
			return count;
		}

		MemoryArena::BlockHeader* MemoryArena::createBlock(BlockHeader* prevBlock) const
		{
			// Operator ::new is expected by the standard to align the memory up to std::max_align_t
			// This is sufficient for our BlockHeader structure, as it is a POD aggregate.
			static_assert(alignof(BlockHeader) <= alignof(std::max_align_t),
			              "BlockHeader alignment is greater than max_align_t");
			BlockHeader* newBlock = static_cast<BlockHeader*>(::operator new(m_BlockSize));
			newBlock->next = nullptr;
			newBlock->usedBytes = 0;

			// Add the new block to the list
			if (prevBlock != nullptr)
			{
				prevBlock->next = newBlock;
			}

			return newBlock;
		}

		void MemoryArena::freeBlock(BlockHeader* block) const
		{
			::operator delete(block);
		}

		ArenaPacket::ArenaPacket(RawPacket* rawPacket, bool ownRawPacket, ParseOptions options)
		    : ArenaPacket(NoParse, rawPacket, ownRawPacket)
		{
			parseLayers(options);
		}

		ArenaPacket::ArenaPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket)
		{
			setRawPacket(NoParse, rawPacket, ownRawPacket);
		}

		ArenaPacket::ArenaPacket(NoParseTag, MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket)
		    : ArenaPacket(std::move(arena))
		{
			setRawPacket(NoParse, rawPacket, ownRawPacket);
		}

		ArenaPacket::ArenaPacket(MemoryArena arena, RawPacket* rawPacket, bool ownRawPacket, ParseOptions options)
		    : ArenaPacket(NoParse, std::move(arena), rawPacket, ownRawPacket)
		{
			parseLayers(options);
		}

		void ArenaPacket::setRawPacket(RawPacket* rawPacket, bool ownPacket, ParseOptions options)
		{
			// Delegate to the no parse overload.
			setRawPacket(NoParse, rawPacket, ownPacket);
			// Parse the layers based on the provided options
			parseLayers(options);
		}

		void ArenaPacket::setRawPacket(NoParseTag, RawPacket* rawPacket, bool ownRawPacket)
		{
			// Destroy the existing packet data, if any

			// Assign the new raw packet
		}

		void ArenaPacket::parseLayers(ParseOptions options)
		{}

		void ArenaPacket::clearParseData()
		{
			MemoryArenaAllocator<Layer> allocator(m_Arena);
			std::allocator_traits<MemoryArenaAllocator<Layer>> allocTraits;

			Layer* curLayer = m_FirstLayer;
			while (curLayer != nullptr)
			{
				Layer* nextLayer = curLayer->getNextLayer();

				if (curLayer->m_IsAllocatedInPacket)
				{
					// This calls the layer destructor, but does not free the memory.
					const size_t objSize = curLayer->getSizeOf();
					PCPP_LOG_DEBUG("Destroying layer of type " << typeid(*curLayer).name() << " of size " << objSize);

					allocTraits.destroy(allocator, curLayer);

					// Uses the arena directly to deallocate the memory, because we pass the size directly.
					// The allocator would have used sizeof(Layer), which is not correct for derived classes.
					m_Arena.deallocate(curLayer, objSize);
				}
				else
				{
					// TODO: This might be valid use case or not?
					throw std::logic_error("Handle layers that aren't in the packet?");
				}

				curLayer = nextLayer;
			}

			// Reset the layers linked list
			m_FirstLayer = nullptr;
			m_LastLayer = nullptr;

			// Clears the arena as everything on it should be deallocated.
			m_Arena.clear();
		}

		void ArenaPacket::setArena(MemoryArena arena)
		{
			clearParseData();
			// Move-assign the new arena.
			m_Arena = std::move(arena);
		}

		MemoryArena ArenaPacket::detachArena()
		{
			// Clears the data allocated on the arena. The function also marks the arena for reuse.
			clearParseData();

			// The move constructor keeps the arena configuration and just transfers the memory.
			// The moved from arena is still valid, but will need to request memory from the free store again.
			return std::move(m_Arena);
		}

		void ArenaPacket::clearPacketData()
		{
			clearParseData();

			// Deallocates the raw packet if owned by the current instance.
			if (m_RawPacket != nullptr && m_OwnRawPacket)
			{
				delete m_RawPacket;
			}

			// Resets the raw packet metadata.
			m_RawPacket = nullptr;
			m_OwnRawPacket = false;
			m_CanReallocateData = false;
			m_RawPacketCapacity = 0;
		}
	}  // namespace experimental
}  // namespace pcpp
