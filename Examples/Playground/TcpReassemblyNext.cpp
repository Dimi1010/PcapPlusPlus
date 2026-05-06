#include "TcpReassemblyNext.h"

#include "IPLayer.h"
#include "TcpLayer.h"
#include "EndianPortable.h"
#include <list>
#include <iterator>

namespace pcpp
{
	namespace internal
	{
		void TcpByteStream::reset(uint32_t seqNum)
		{
			// Clear all data in the reorder buffer.
			returnFreeParts(m_ReorderBuffer);
			m_ExpectedSeqNum = seqNum;
		}

		TcpByteStream::PartBufferList TcpByteStream::takeFreeParts(size_t count)
		{
			PartBufferList takenParts;
			if (count <= m_FreeListCache.size())
			{
				takenParts.splice(takenParts.begin(), m_FreeListCache, m_FreeListCache.begin(),
				                  std::next(m_FreeListCache.begin(), count));
			}
			else
			{
				// Transfer the entire cache to taken.
				takenParts.splice(takenParts.begin(), m_FreeListCache);
				// Resize to the requested count. This will expand the list until we have enough parts.
				takenParts.resize(count);
			}

			return takenParts;
		}

		void TcpByteStream::returnFreeParts(PartBufferList& parts)
		{
			// TODO: Free data buffer on nodes?

			// TODO: Profile verification needed.
			// Link the parts to the start of the free list as they are probably hot in cache after being used, and we
			// want to reuse them as soon as possible.
			m_FreeListCache.splice(m_FreeListCache.begin(), parts);
		}

		void TcpByteStream::insertSeqToReorderBuffer(uint32_t seqNum, uint8_t const* data, size_t dataLen,
		                                             SeqFlags flags)
		{
			uint32_t nextSeqNum = internal::calcNextSeqNum(seqNum, dataLen, flags);

			// TODO: Attempt to merge with other OOS parts if they are contiguous.
			// If the new part is not contiguous with any existing OOS part, we can simply add it as a new part
			// in the stream.

			if (m_ReorderBuffer.empty())
			{
				// The reorder buffer is empty.
				// Create a new part and fill it.

				auto newPartsList = takeFreeParts(1);
				PCPP_ASSERT(newPartsList.size() == 1, "Free parts pool should be able to provide a part");

				auto& newPart = newPartsList.front();

				// TODO: Extract to a procedure.
				// Allocate and copy the data for the new part.
				if (newPart.dataCap < dataLen)
				{
					if (newPart.ownsData)
					{
						delete[] newPart.data;
					}

					newPart.data = new uint8_t[dataLen];
					newPart.dataCap = dataLen;
					newPart.ownsData = true;
				}

				std::memcpy(newPart.data, data, dataLen);
				newPart.dataLen = dataLen;
				newPart.seqNum = seqNum;
				newPart.seqFlags = flags;

				// Reorder buf is empty. We can just overwrite it.
				m_ReorderBuffer = std::move(newPartsList);
				return;
			}

			// We have at least one part in the reorder buffer.
			// Insert the new part into the reorder buffer and link it to its closest neighbors in the stream.

			auto nextPartIt = m_ReorderBuffer.begin();
			auto prevPartIt = m_ReorderBuffer.end();  // Assigned to end as a sentinel value for "no previous part".

			// Find the first part that starts after or at the sequence number of the new part, if any.
			while (nextPartIt != m_ReorderBuffer.end() && internal::compareSeqNum(nextPartIt->seqNum, seqNum) < 0)
			{
				prevPartIt = nextPartIt;
				++nextPartIt;
			}

			// If prevPart is not null, that means we have a pending segment before the new part.
			// If nextPart is not null, that means we have a segment after the new part.

			// For prevPart and newPart the possible overlap cases are:
			// 1. No overlap: No bytes are duplicated
			// 2. Right overlap: Some of the bytes in prevPart are duplicated in newPart
			//
			// No full overlap is possible, since prevPart starts before newPart.
			// Otherwise the loop would have stopped when prevPart was nextPart.

			if (prevPartIt != m_ReorderBuffer.end())  // <- checks with the sentinel assigned earlier.
			{
				if (internal::compareSeqNum(prevPartIt->nextSeqNum(), seqNum) > 0)
				{
					// Possible right overlap of prevPart.
					uint32_t seqOverlap = prevPartIt->nextSeqNum() - seqNum;

					// Data byte overlap, excluding possible phantom bytes
					uint32_t leftTrimBytes = seqOverlap - prevPartIt->seqFlags.finFlag;

					PCPP_ASSERT(
					    leftTrimBytes < dataLen,
					    "New part is fully enveloped by previous part, prevPart should have been nextPart on last cycle.");

					// Retarget to the new effective span, ignoring the prevPart.
					seqNum += seqOverlap;
					// Remove the syn flag, since we are padding from the left.
					flags.synFlag = false;

					data += leftTrimBytes;
					dataLen -= leftTrimBytes;

					// NextSeqNum should be unaffected by the trim, since the right border is unchanged.
					PCPP_ASSERT(nextSeqNum == internal::calcNextSeqNum(seqNum, dataLen, flags),
					            "Left trim should not affect the next expected sequence number");
				}
			}

			// For nextPart and newPart the possible overlap cases are:
			// 1. No overlap: No bytes are duplicated
			// 2. Left overlap: Some of the bytes in nextPart are duplicated in newPart
			// 3. Full overlap: nextPart is fully enveloped by newPart, meaning all of its bytes are duplicated
			// in newPart.
			// 3.a In this case, check further next parts, filling in the gaps until we consume all the new
			//   part's bytes or we find a non-overlapping part.
			while (nextPartIt != m_ReorderBuffer.end())
			{
				// Notable edge case:
				// If nextPart contains a SYN flag, that means we are attempting to inject data before the SYN
				// segment. which is ill-formed as it does not conform to TCP spec.
				if (nextPartIt->seqFlags.synFlag)
				{
					throw std::runtime_error("Insertion prior to SYN flag");
				}

				// Compare if left border of nextPart is before or at the right border of the new part.
				if (internal::compareSeqNum(nextPartIt->seqNum, nextSeqNum) < 0)
				{
					// Conceptually we have 2 cases to handle here.
					// 1. The new buffer terminates inside nextPart.
					// 2. The new buffer extends past the end of nextPart.
					//    It may contain new data or overlap with nextPart + 1.
					//
					// In both cases we need to trim the overlapping part with nextPart.
					// In case 2. we also need to save the extra data past nextPart, and redo with nextPart + 1.
					//
					// The buffer can thus be split into two subsections.
					// 1. Valid new data prior to nextPart.
					// 2. Unprocessed data past the end of nextPart.

					size_t trimLen = nextPartIt->seqNum - internal::calcTrueSeqNum(seqNum, flags);
					SeqFlags trimFlags = flags;
					flags.finFlag = false;  // Clear the FIN flag since we are trimming from the right.

					if (internal::compareSeqNum(nextSeqNum, nextPartIt->nextSeqNum()) > 0)
					{
						// We may have new data that goes past nextPart.

						// Notable edge case:
						// If the nextPart contains a FIN flag, that means it is supposed to be the last
						// sequence packet. In that case, any data after it is ill-formed as it does not conform
						// to TCP spec.
						if (nextPartIt->seqFlags.finFlag)
						{
							// TODO: Handle error.
							throw std::runtime_error("Sequence Error. Injecting data after FIN segment");
						}

						// Records the extra data that extends past nextPart.
						uint32_t offset = nextPartIt->nextSeqNum() - internal::calcTrueSeqNum(seqNum, flags);
						uint8_t const* exData = data + offset;
						size_t exDataLen = dataLen - offset;
						uint32_t exDataSeq = nextPartIt->nextSeqNum();
						SeqFlags exFlags = flags;
						exFlags.synFlag = false;  // Clear the SYN flag since we are trimming from the left.

						// Write the buffer [seqNum, nextPart->seqNum).
						// Only write if we actually have new data prior to nextPart
						if (trimLen > 0)
						{
							auto newPartsList = takeFreeParts(1);
							PCPP_ASSERT(newPartsList.size() == 1, "Free parts pool should be able to provide a part");

							TcpStreamBufferedPart& newPart = newPartsList.front();

							// Populate the new node.
							// Allocate and copy the data for the new part.
							// TODO: Extract to a procedure.
							if (newPart.dataCap < trimLen)
							{
								if (newPart.ownsData)
								{
									delete[] newPart.data;
								}
								newPart.data = new uint8_t[trimLen];
								newPart.dataCap = trimLen;
								newPart.ownsData = true;
							}

							std::memcpy(newPart.data, data, trimLen);
							newPart.dataLen = trimLen;
							newPart.seqNum = seqNum;
							newPart.seqFlags = trimFlags;

							PCPP_ASSERT(newPart.dataLen > 0, "Adding 0 data sequence is pointless.");

							// Transfer the new part to the reorder buffer between prevPart and nextPart.
							m_ReorderBuffer.splice(nextPartIt, newPartsList);
						}

						// Advance parts and redo check.
						prevPartIt = nextPartIt;
						++nextPartIt;

						data = exData;
						dataLen = exDataLen;
						seqNum = exDataSeq;
						flags = exFlags;

						PCPP_ASSERT(nextSeqNum == internal::calcNextSeqNum(seqNum, dataLen, flags),
						            "Next SEQ number should be unchanged.");
					}
					else
					{
						// No extended data after nextPart, we can simply trim the new part to the
						// non-overlapping section and link it before nextPart.
						dataLen = trimLen;
						flags = trimFlags;
						break;
					}
				}
				else
				{
					// No overlap. nextPart is fully after newPart.
					break;
				}
			}

			// Add the new part to the OOS buffer and link it to its neighbors.
			auto newPartsList = takeFreeParts(1);
			PCPP_ASSERT(newPartsList.size() == 1, "Free parts pool should be able to provide a part");
			auto& newPart = newPartsList.front();

			// TODO Edge: If a SYN or FIN flag is added without data, possibly merge it to a nearby fragment.
			PCPP_ASSERT(dataLen > 0, "Adding 0 data sequence is pointless.");

			// Populate the new node.
			// TODO: Extract to a procedure.
			if (newPart.dataCap < dataLen)
			{
				if (newPart.ownsData)
				{
					delete[] newPart.data;
				}
				newPart.data = new uint8_t[dataLen];
				newPart.dataCap = dataLen;
				newPart.ownsData = true;
			}

			std::memcpy(newPart.data, data, dataLen);
			newPart.dataLen = dataLen;
			newPart.seqNum = seqNum;
			newPart.seqFlags = flags;

			// Insert the new part between prevPart and nextPart.
			m_ReorderBuffer.splice(nextPartIt, newPartsList);
		}

		TcpByteStream::HOLUnblockResult TcpByteStream::tryUnblockHeadOfLine(uint32_t seqNum)
		{
			auto headIt = m_ReorderBuffer.begin();
			auto endIt = m_ReorderBuffer.end();

			if (headIt == endIt || internal::compareSeqNum(headIt->seqNum, seqNum) > 0)
			{
				// The HOL sequence number is still higher than the sequence number we want to unblock on, so we cannot
				// unblock anything.
				return HOLUnblockResult();
			}

			auto currentIt = headIt;
			auto nextIt = std::next(currentIt);

			// Advance until the first element that is past the unblocking sequence number.
			while (nextIt != endIt && internal::compareSeqNum(currentIt->nextSeqNum(), seqNum) <= 0)
			{
				currentIt = nextIt;
				nextIt = std::next(currentIt);
			}

			// Advance until the first element that is not contiguous with the part that is after the head of line.
			while (nextIt != endIt && internal::compareSeqNum(currentIt->nextSeqNum(), nextIt->seqNum) == 0)
			{
				currentIt = nextIt;
				nextIt = std::next(currentIt);
			}

			// Checks if the list is correctly ordered, with no overlaps and the head being the lowest sequence number.
			PCPP_ASSERT(nextIt == endIt || internal::compareSeqNum(currentIt->nextSeqNum(), nextIt->seqNum) < 0,
			            "If next part exists, it must be of higher sequence number.");

			HOLUnblockResult result;
			// Transfers all elements in the range [headIt, nextIt) from the reorder buffer to tne unblocked list.
			// This operation does not involve any copying of the elements, but only relinks the nodes.
			result.unblockedParts.splice(result.unblockedParts.begin(), m_ReorderBuffer, headIt, nextIt);
			return result;
		}
	}  // namespace internal

	TcpReassemblyV2::ReassemblyStatus TcpReassemblyV2::reassemblePacket(Packet& packet)
	{
		// TODO: Run Garbage collection on Connections.

		// calculate packet's source and dest IP address
		if (!packet.isPacketOfType(IP))
		{
			return ReassemblyStatus::NonIpPacket;
		}

		const IPLayer* ipLayer = packet.getLayerOfType<IPLayer>();
		IPAddress srcIP = ipLayer->getSrcIPAddress();
		IPAddress dstIP = ipLayer->getDstIPAddress();

		// Ignore non-TCP packets
		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>(true);  // lookup in reverse order
		if (tcpLayer == nullptr)
		{
			return ReassemblyStatus::NonTcpPacket;
		}

		// Ignore the packet if it's an ICMP packet that has a TCP layer
		// Several ICMP messages (like "destination unreachable") have TCP data as part of the ICMP message.
		// This is not real TCP data and packet can be ignored
		if (packet.isPacketOfType(ICMP))
		{
			PCPP_LOG_DEBUG(
			    "Packet is of type ICMP so TCP data is probably part of the ICMP message. Ignoring this packet");
			return ReassemblyStatus::NonTcpPacket;
		}

		// set the TCP payload size
		size_t tcpPayloadSize = tcpLayer->getLayerPayloadSize();

		// calculate if this packet has FIN or RST flags
		bool isFin = (tcpLayer->getTcpHeader()->finFlag == 1);
		bool isRst = (tcpLayer->getTcpHeader()->rstFlag == 1);
		bool isFinOrRst = isFin || isRst;

		// TODO: Do not ignore ACK packets. Use them to sync the stream position.

		// ignore ACK packets or TCP packets with no payload (except for SYN, FIN or RST packets which we'll later need)
		if (tcpPayloadSize == 0 && tcpLayer->getTcpHeader()->synFlag == 0 && !isFinOrRst)
		{
			return ReassemblyStatus::Ignore_PacketWithNoData;
		}

		// Calculate flow key based on srcIP, dstIP, srcPort, dstPort.
		FlowKey flowKey = hash5Tuple(&packet);

		// Find connection by flow key. If not found, create a new connection.
		auto it = m_Connections.find(flowKey);
		if (it == m_Connections.end())
		{
			// Open new tcpConn.
			it = m_Connections.emplace(flowKey, TcpConnection()).first;
			auto& tcpConn = it->second;
			tcpConn.metadata.srcIP = srcIP;
			tcpConn.metadata.dstIP = dstIP;
			tcpConn.metadata.srcPort = tcpLayer->getSrcPort();
			tcpConn.metadata.dstPort = tcpLayer->getDstPort();
			tcpConn.metadata.flowKey = flowKey;

			// TODO: Set start time of the connection.
			// tcpConn.metadata.setStartTime(currTime);
		}

		auto& tcpConn = it->second;
		if (tcpConn.closed)
		{
			PCPP_LOG_DEBUG("Ignoring packet of already closed flow [0x" << std::hex << flowKey << "]");
			return ReassemblyStatus::Ignore_PacketOfClosedFlow;
		}

		// Establish tcpConn sides.
		uint32_t srcPort = tcpLayer->getSrcPort();

		auto sourceEquals = [](TcpConnectionSide const& side, IPAddress const& ip, uint16_t port) -> bool {
			return side.srcIP == ip && side.srcPort == port;
		};

		// Find the side of the connection that matches the packet, if any.
		TcpConnectionSide* currentSide = nullptr;
		for (int i = 0; i < tcpConn.openStreamSides; i++)
		{
			if (sourceEquals(tcpConn.sides[i], srcIP, srcPort))
			{
				currentSide = &tcpConn.sides[i];
				break;
			}
		}

		bool openedNewSide = false;
		if (currentSide == nullptr)
		{
			// We have a flow error, if we have 2 open sides and we did not match.
			if (tcpConn.openStreamSides >= 2)
			{
				PCPP_LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
				return ReassemblyStatus::Error_PacketDoesNotMatchFlow;
			}

			// We have an unknown side, but we still have room to open a new one, so we can open it.
			PCPP_LOG_DEBUG("Found new stream side for flow, opening new side. "
			               "[Flow="
			               << std::hex << flowKey << "; Stream=" << tcpConn.openStreamSides << "]");

			currentSide = &tcpConn.sides[tcpConn.openStreamSides++];
			currentSide->srcIP = srcIP;
			currentSide->srcPort = srcPort;
			// currentSide->stream.reset();

			openedNewSide = true;
		}

		PCPP_ASSERT(currentSide != nullptr, "Current side should have been identified by this point");

		uint32_t seqNum = be32toh(tcpLayer->getTcpHeader()->sequenceNumber);
		uint8_t const* payloadData = tcpLayer->getLayerPayload();
		size_t payloadLen = tcpLayer->getLayerPayloadSize();
		SeqFlags flags;
		flags.synFlag = tcpLayer->getTcpHeader()->synFlag == 1;
		flags.finFlag = tcpLayer->getTcpHeader()->finFlag == 1;

		// Insert the packet payload into the reassembly stream.
		auto onDataReady = [this, &tcpConn, currentSide](internal::TcpByteStreamDataReadyEvent const& event) {
			int8_t sideIndex = currentSide - tcpConn.sides.data();

			switch (m_OnDataReady.getType())
			{
			case DataReadyCallback::Type::Single:
			{
				auto* cb = m_OnDataReady.getSingleCallback();
				PCPP_ASSERT(cb != nullptr, "Single callback should not be null");
				if (*cb == nullptr)
				{
					PCPP_LOG_DEBUG("No single callback registered, skipping data ready event.");
					return;
				}

				size_t missingBytes = event.getLeadingMissingBytes();
				for (auto& part : event.extraParts)
				{
					PCPP_LOG_DEBUG("Invoking single callback for part with SEQ=" << part.seqNum
					                                                             << ";LEN=" << part.dataLen);
					TcpStreamDataV2 sd(part.data, part.dataLen, missingBytes, {});
					TcpDataReadyCtx ctx{ m_Config };
					(*cb)(sideIndex, sd, tcpConn.metadata, ctx);
				}
				break;
			}
			case DataReadyCallback::Type::Batch:
			{
				auto* cb = m_OnDataReady.getBatchCallback();
				PCPP_ASSERT(cb != nullptr, "Batch callback should not be null");
				if (*cb == nullptr)
				{
					PCPP_LOG_DEBUG("No batch callback registered, skipping data ready event.");
					return;
				}

				PCPP_LOG_DEBUG("Invoking batch callback.");

				TcpStreamDataV2Batch batch;
				TcpDataReadyCtx ctx{ m_Config };
				(*cb)(sideIndex, batch, tcpConn.metadata, ctx);
				break;
			}
			}
		};

		// TODO: If we have an ACK number, flush the opposite side to that ACK number.
		// We are unlikely to receive packets that contain ACKed data, so we can mark the gaps as missing.

		currentSide->stream.insertSeq(onDataReady, seqNum, payloadData, payloadLen, flags);

		// TODO: Check if the stream closed. E.g. a FIN flag was processed.
		// TODO: Check if we have RST. Force close stream.

		return ReassemblyStatus();
	}

	TcpReassemblyV2::ReassemblyStatus TcpReassemblyV2::reassemblePacket(RawPacket& rawPacket)
	{
		Packet packet(&rawPacket);
		return reassemblePacket(packet);
	}

	void TcpReassemblyV2::DataReadyCallback::swapToType(Type newType) noexcept
	{
		if (newType == m_Type)
		{
			return;
		}

		destroyActiveMem();

		switch (newType)
		{
		case Type::Single:
			new (&m_SingleCallback) OnTcpDataReady();
			break;
		case Type::Batch:
			new (&m_BatchCallback) OnTcpDataReadyBatch();
			break;
		default:
			throw std::logic_error("Invalid callback type");
		}
		m_Type = newType;
	}

	void TcpReassemblyV2::DataReadyCallback::destroyActiveMem() noexcept
	{
		switch (m_Type)
		{
		case Type::Single:
			m_SingleCallback.~OnTcpDataReady();
			break;
		case Type::Batch:
			m_BatchCallback.~OnTcpDataReadyBatch();
			break;
		default:
			throw std::logic_error("Invalid callback type");
		}
	}
}  // namespace pcpp