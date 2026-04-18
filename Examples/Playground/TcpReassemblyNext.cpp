#include "TcpReassemblyNext.h"

#include "IPLayer.h"
#include "TcpLayer.h"

namespace pcpp
{
	namespace internal
	{
		inline TcpStreamSeqPart* TcpByteStream::getPart(PartId partId)
		{
			if (partId == TcpStreamSeqPart::INVALID_PART_ID)
			{
				return nullptr;
			}

			PCPP_ASSERT(partId < m_Parts.size(), "Accessing invalid part");
			return &m_Parts[partId];
		}

		inline TcpByteStream::PartId TcpByteStream::getPartId(TcpStreamSeqPart const* part) const
		{
			if (part == nullptr)
			{
				return TcpStreamSeqPart::INVALID_PART_ID;
			}

			auto partId = part - &m_Parts[0];
			PCPP_ASSERT(partId >= 0 && partId < m_Parts.size(), "Part pointer is out of range of the parts vector");
			return partId;
		}

		void TcpByteStream::insertNodeAfter(NodeIndexList& list, TcpStreamSeqPart::PartId prevId,
		                                    TcpStreamSeqPart* newNode)
		{
			return insertNodeAfter(list, getPart(prevId), newNode);
		}

		void TcpByteStream::insertNodeAfter(NodeIndexList& list, TcpStreamSeqPart* prevNode, TcpStreamSeqPart* newNode)
		{
			PCPP_ASSERT(newNode != nullptr, "New node to link cannot be null");
			PCPP_ASSERT(prevNode == nullptr || newNode != prevNode, "New node cannot be linked to itself as previous");
			PCPP_ASSERT(newNode->nextId == TcpStreamSeqPart::INVALID_PART_ID &&
			                newNode->prevId == TcpStreamSeqPart::INVALID_PART_ID,
			            "New node must be unlinked.");

			PartId newNodeId = getPartId(newNode);
			PartId prevId = getPartId(prevNode);

			PCPP_ASSERT(newNodeId != TcpStreamSeqPart::INVALID_PART_ID, "New node must have a valid id");
			PCPP_ASSERT(prevNode == nullptr || prevId != TcpStreamSeqPart::INVALID_PART_ID,
			            "Prev must have a valid id");

			if (prevNode == nullptr)
			{
				// Inserting at the head.
				PartId nextNodeId = list.head;
				TcpStreamSeqPart* nextNode = getPart(nextNodeId);

				if (nextNode != nullptr)
				{
					nextNode->prevId = newNodeId;
				}

				newNode->nextId = nextNodeId;
				newNode->prevId = TcpStreamSeqPart::INVALID_PART_ID;
				list.head = newNodeId;
				return;
			}

			// Inserting at position.
			PartId nextId = prevNode->nextId;
			TcpStreamSeqPart* nextNode = getPart(nextId);

			if (nextNode != nullptr)
			{
				// Inserting at the middle, we have a next node.
				newNode->nextId = nextId;
				nextNode->prevId = newNodeId;
			}
			else
			{
				// Inserting at the tail, no next node.
				newNode->nextId = TcpStreamSeqPart::INVALID_PART_ID;
			}

			newNode->prevId = prevId;
			prevNode->nextId = newNodeId;
		}

		void TcpByteStream::insertNodeRangeAfter(NodeIndexList& list, TcpStreamSeqPart::PartId prevId,
		                                         TcpStreamSeqPart* startNode, TcpStreamSeqPart* endNode)
		{
			return insertNodeRangeAfter(list, getPart(prevId), startNode, endNode);
		}

		void TcpByteStream::insertNodeRangeAfter(NodeIndexList& list, TcpStreamSeqPart* prevNode,
		                                         TcpStreamSeqPart* startNode, TcpStreamSeqPart* endNode)
		{
			PCPP_ASSERT(startNode != nullptr && endNode != nullptr, "Start and end nodes cannot be null");
			PCPP_ASSERT(startNode->prevId == TcpStreamSeqPart::INVALID_PART_ID,
			            "Start node must not be preceeded by a node.");
			PCPP_ASSERT(endNode->nextId == TcpStreamSeqPart::INVALID_PART_ID,
			            "End node must not be followed by a node.");

			// Single node range.
			if (startNode == endNode)
			{
				insertNodeAfter(list, prevNode, startNode);
				return;
			}

			auto debugCanReachTail = [=]() -> bool {
				TcpStreamSeqPart* current = startNode;
				while (current != nullptr)
				{
					if (current == endNode)
					{
						return true;
					}
					current = getPart(current->nextId);
				}
				return false;
			};
			PCPP_ASSERT(debugCanReachTail(), "Start node should be able to reach end node by following next pointers");

			if (prevNode == nullptr)
			{
				// Inserting at the head, we need to update the head pointer.
				PartId nextNodeId = list.head;

				TcpStreamSeqPart* nextNode = getPart(nextNodeId);
				if (nextNode != nullptr)
				{
					nextNode->prevId = getPartId(endNode);
				}

				endNode->nextId = nextNodeId;
				startNode->prevId = TcpStreamSeqPart::INVALID_PART_ID;
				list.head = getPartId(startNode);
				return;
			}

			// Inserting at position.

			PartId nextNodeId = prevNode->nextId;
			TcpStreamSeqPart* nextNode = getPart(nextNodeId);

			// Link the end node to the next node, if it exists.
			if (nextNode != nullptr)
			{
				// Inserting at the middle, we have a next node.
				endNode->nextId = nextNodeId;
				nextNode->prevId = getPartId(endNode);
			}
			else
			{
				// Inserting at the tail, no next node.
				endNode->nextId = TcpStreamSeqPart::INVALID_PART_ID;
			}

			// Link the start node to the previous node.
			startNode->prevId = getPartId(prevNode);
			prevNode->nextId = getPartId(startNode);
		}

		void TcpByteStream::extractNode(NodeIndexList& list, TcpStreamSeqPart* node)
		{
			PCPP_ASSERT(node != nullptr, "Node to extract cannot be null");

			PartId nodeId = getPartId(node);
			PCPP_ASSERT(nodeId != TcpStreamSeqPart::INVALID_PART_ID, "Node to extract must have a valid id");

			PartId prevId = node->prevId;
			PartId nextId = node->nextId;

			if (prevId != TcpStreamSeqPart::INVALID_PART_ID)
			{
				TcpStreamSeqPart* prevNode = getPart(prevId);
				prevNode->nextId = nextId;
			}
			else
			{
				// We are extracting the head of the list, so we need to update the head pointer.
				list.head = nextId;
			}

			if (nextId != TcpStreamSeqPart::INVALID_PART_ID)
			{
				TcpStreamSeqPart* nextNode = getPart(nextId);
				nextNode->prevId = prevId;
			}

			// Unlink the extracted node.
			node->prevId = TcpStreamSeqPart::INVALID_PART_ID;
			node->nextId = TcpStreamSeqPart::INVALID_PART_ID;
		}

		void TcpByteStream::extractNodeRange(NodeIndexList& list, TcpStreamSeqPart* startNode,
		                                     TcpStreamSeqPart* endNode)
		{
			PCPP_ASSERT(startNode != nullptr && endNode != nullptr, "Start and end nodes cannot be null");

			PartId startNodeId = getPartId(startNode);
			PartId endNodeId = getPartId(endNode);

			PCPP_ASSERT(startNodeId != TcpStreamSeqPart::INVALID_PART_ID &&
			                endNodeId != TcpStreamSeqPart::INVALID_PART_ID,
			            "Start and end nodes must have valid ids");

			if (startNodeId == endNodeId)
			{
				// The range is a single node, we can simply extract that node.
				extractNode(list, startNode);
				return;
			}

			auto debugCanReachTail = [=]() -> bool {
				TcpStreamSeqPart* current = startNode;
				while (current != nullptr)
				{
					if (current == endNode)
					{
						return true;
					}
					current = getPart(current->nextId);
				}
				return false;
			};
			PCPP_ASSERT(debugCanReachTail(), "Start node should be able to reach end node by following next pointers");

			PartId prevId = startNode->prevId;
			PartId nextId = endNode->nextId;

			// Multiple nodes in the range.
			if (startNodeId == list.head)
			{
				// The range begins with the head of the list, so we need to update the head pointer.
				list.head = nextId;
			}
			else
			{
				TcpStreamSeqPart* prevNode = getPart(prevId);
				PCPP_ASSERT(prevNode != nullptr, "Previous node must be valid if start node is not head");
				prevNode->nextId = nextId;
			}

			if (nextId != TcpStreamSeqPart::INVALID_PART_ID)
			{
				TcpStreamSeqPart* nextNode = getPart(nextId);
				PCPP_ASSERT(nextNode != nullptr, "Next node must be valid if end node is not tail");
				nextNode->prevId = prevId;
			}

			// Unlink the extracted nodes.
			startNode->prevId = TcpStreamSeqPart::INVALID_PART_ID;
			endNode->nextId = TcpStreamSeqPart::INVALID_PART_ID;
		}

		TcpStreamSeqPart* TcpByteStream::takeFreePart()
		{
			if (m_FreeSlotsList.head == TcpStreamSeqPart::INVALID_PART_ID)
			{
				// Using emplace back to utilize the automatic growth of the vector.
				if (m_Parts.size() == std::numeric_limits<uint32_t>::max())
				{
					throw std::overflow_error("Reached maximum number of parts");
				}

				m_Parts.emplace_back();
				return &m_Parts.back();
			}

			PCPP_ASSERT(m_FreeSlotsList.head < m_Parts.size(), "Free part id is out of range of the parts vector");
			TcpStreamSeqPart* newPart = nullptr;
			newPart = &m_Parts[m_FreeSlotsList.head];

			// When parts are not in use, they are linked together with other free parts using the nextId
			// attribute. This makes the logical free list of parts, and allows us to reuse parts without
			// having to search for them or maintain a separate free list.
			m_FreeSlotsList.head = newPart->nextId;
			newPart->nextId = TcpStreamSeqPart::INVALID_PART_ID;
			newPart->prevId = TcpStreamSeqPart::INVALID_PART_ID;
			return newPart;
		}

		void TcpByteStream::insertSeqToReorderBuffer(uint32_t seqNum, uint8_t const* data, size_t dataLen,
		                                             SeqFlags flags)
		{
			uint32_t nextSeqNum = internal::calcNextSeqNum(seqNum, dataLen, flags);

			// TODO: Attempt to merge with other OOS parts if they are contiguous.
			// If the new part is not contiguous with any existing OOS part, we can simply add it as a new part
			// in the stream.

			auto* firstPart = getPart(m_ReorderList.head);
			if (firstPart == nullptr)
			{
				// The reorder buffer is empty.
				// Create a new part and fill it.

				TcpStreamSeqPart* newPart = takeFreePart();
				PCPP_ASSERT(newPart != nullptr, "Failed to get free part from the pool");
				uint32_t index = getPartId(newPart);

				newPart->data = data;
				newPart->dataLen = dataLen;
				newPart->seqNum = seqNum;
				newPart->seqFlags = flags;

				// First node, no other nodes to link to.
				insertNodeAfter(m_ReorderList, nullptr, newPart);
				return;
			}

			// We have at least one part in the reorder buffer.
			// Insert the new part into the reorder buffer and link it to its closest neighbors in the stream.
			PCPP_ASSERT(firstPart != nullptr, "Reorder buffer should not be empty");

			TcpStreamSeqPart* nextPart = firstPart;
			TcpStreamSeqPart* prevPart = nullptr;

			// Find the first part that starts after or at the sequence number of the new part, if any.
			while (nextPart != nullptr && internal::compareSeqNum(nextPart->seqNum, seqNum) < 0)
			{
				prevPart = nextPart;
				nextPart = getPart(nextPart->nextId);
			}

			// If prevPart is not null, that means we have a pending segment before the new part.
			// If nextPart is not null, that means we have a segment after the new part.

			// For prevPart and newPart the possible overlap cases are:
			// 1. No overlap: No bytes are duplicated
			// 2. Right overlap: Some of the bytes in prevPart are duplicated in newPart
			//
			// No full overlap is possible, since prevPart starts before newPart.
			// Otherwise the loop would have stopped when prevPart was nextPart.

			if (prevPart != nullptr)
			{
				if (internal::compareSeqNum(prevPart->nextSeqNum(), seqNum) > 0)
				{
					// Possible right overlap of prevPart.
					uint32_t seqOverlap = prevPart->nextSeqNum() - seqNum;

					// Data byte overlap, excluding possible phantom bytes
					uint32_t leftTrimBytes = seqOverlap - prevPart->seqFlags.finFlag;

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
			while (nextPart != nullptr)
			{
				// Notable edge case:
				// If nextPart contains a SYN flag, that means we are attempting to inject data before the SYN
				// segment. which is ill-formed as it does not conform to TCP spec.
				if (nextPart->seqFlags.synFlag)
				{
					throw std::runtime_error("Insertion prior to SYN flag");
				}

				// Compare if left border of nextPart is before or at the right border of the new part.
				if (internal::compareSeqNum(nextPart->seqNum, nextSeqNum) < 0)
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

					size_t trimLen = nextPart->seqNum - internal::calcTrueSeqNum(seqNum, flags);
					SeqFlags trimFlags = flags;
					flags.finFlag = false;  // Clear the FIN flag since we are trimming from the right.

					if (internal::compareSeqNum(nextSeqNum, nextPart->nextSeqNum()) > 0)
					{
						// We may have new data that goes past nextPart.

						// Notable edge case:
						// If the nextPart contains a FIN flag, that means it is supposed to be the last
						// sequence packet. In that case, any data after it is ill-formed as it does not conform
						// to TCP spec.
						if (nextPart->seqFlags.finFlag)
						{
							// TODO: Handle error.
							throw std::runtime_error("Sequence Error. Injecting data after FIN segment");
						}

						// Records the extra data that extends past nextPart.
						uint32_t offset = nextPart->nextSeqNum() - internal::calcTrueSeqNum(seqNum, flags);
						uint8_t const* exData = data + offset;
						size_t exDataLen = dataLen - offset;
						uint32_t exDataSeq = nextPart->nextSeqNum();
						SeqFlags exFlags = flags;
						exFlags.synFlag = false;  // Clear the SYN flag since we are trimming from the left.

						// Write the buffer [seqNum, nextPart->seqNum).
						// Only write if we actually have new data prior to nextPart
						if (trimLen > 0)
						{
							// We have to save the part ids before we create the new part.
							// Get free part MAY REALLOCATE the parts storage buffer, invalidating all pointers.
							uint32_t prevId = getPartId(prevPart);
							uint32_t nextId = getPartId(nextPart);

							// Add the new part to the OOS buffer and link it to its neighbors.
							TcpStreamSeqPart* newPart = takeFreePart();
							uint32_t newId = getPartId(newPart);

							// Restore the pointers after possible reallocation.
							prevPart = getPart(prevId);
							nextPart = getPart(nextId);

							// Populate the new node.
							newPart->data = data;
							newPart->dataLen = trimLen;
							newPart->seqNum = seqNum;
							newPart->seqFlags = trimFlags;

							PCPP_ASSERT(newPart->dataLen > 0, "Adding 0 data sequence is pointless.");

							// Link the new node.
							insertNodeAfter(m_ReorderList, prevPart, newPart);
						}

						// Advance parts and redo check.
						prevPart = nextPart;
						nextPart = getPart(nextPart->nextId);

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

			// We have to save the part ids before we create the new part.
			// Get free part MAY REALLOCATE the parts storage buffer, invalidating all pointers.
			uint32_t prevId = getPartId(prevPart);
			uint32_t nextId = getPartId(nextPart);

			// Add the new part to the OOS buffer and link it to its neighbors.
			TcpStreamSeqPart* newPart = takeFreePart();
			uint32_t newId = getPartId(newPart);

			// Restore the pointers after possible reallocation.
			prevPart = getPart(prevId);
			nextPart = getPart(nextId);

			// Populate the new node.

			newPart->data = data;
			newPart->dataLen = dataLen;
			newPart->seqNum = seqNum;
			newPart->seqFlags = flags;

			// TODO Edge: If a SYN or FIN flag is added without data, possibly merge it to a nearby fragment.
			PCPP_ASSERT(newPart->dataLen > 0, "Adding 0 data sequence is pointless.");
			insertNodeAfter(m_ReorderList, prevPart, newPart);
		}

		TcpByteStream::HOLUnblockResult TcpByteStream::tryUnblockHeadOfLine(uint32_t expSeqNum)
		{
			TcpStreamSeqPart* head = getPart(m_ReorderList.head);

			PCPP_ASSERT(head != nullptr, "The head part must be valid.");
			if (head == nullptr || internal::compareSeqNum(head->seqNum, expSeqNum) != 0)
			{
				// The head part does not have the expected sequence number, so we cannot unlink an ordered chain.
				return HOLUnblockResult();
			}

			TcpStreamSeqPart* current = head;
			TcpStreamSeqPart* next = getPart(current->nextId);

			while (next != nullptr && internal::compareSeqNum(current->nextSeqNum(), next->seqNum) == 0)
			{
				current = next;
				next = getPart(current->nextId);
			}

			// Checks if the list is correctly ordered, with no overlaps and the head being the lowest sequence number.
			PCPP_ASSERT(next == nullptr || internal::compareSeqNum(current->nextSeqNum(), next->seqNum) < 0,
			            "If next part exists, it must be of higher sequence number.");

			uint32_t headId = m_ReorderList.head;  // Save the head id.

			// Unlink current from next, making current the new tail of the chain.
			extractNodeRange(m_ReorderList, head, current);

			HOLUnblockResult result;
			result.head = head;
			result.tail = current;
			result.headId = headId;
			return result;
		}

		TcpByteStream::HOLUnblockResult TcpByteStream::forceUnblockHeadOfLineTo(uint32_t expSeqNum)
		{
			return HOLUnblockResult();
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

		FlowKey flowKey = 0;  // TODO: Calculate flow key based on srcIP, dstIP, srcPort, dstPort.

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

		// Establish tcpConn side.

		auto onDataReady = [this, &tcpConn](internal::TcpByteStreamView const& rawView) {
			// m_OnMessageReady();
		};

		auto& activeSide = tcpConn.side[0];
		activeSide.stream.insertSeq(onDataReady, 0, nullptr, 0, {});

		return ReassemblyStatus();
	}
}  // namespace pcpp