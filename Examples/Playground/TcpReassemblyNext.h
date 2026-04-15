#pragma once

#define NOMINMAX

#include <iostream>
#include "TcpReassembly.h"
#include "AssertionUtils.h"
#include "PacketUtils.h"

#define PCPP_LOG_DEBUG(m) std::cerr << m << '\n';

namespace pcpp
{
	struct SeqFlags
	{
		/// @brief A SYN flag is part of the sequence part.
		///
		/// This is used to indicate that the part contains a SYN header,
		/// which adds 1 byte of sequence space prior to the payload.
		bool synFlag = false;

		/// @brief A FIN flag is part of the sequence part.
		///
		/// This is used to indicate that the part contains a FIN header,
		/// which adds 1 byte of sequence space after the payload.
		bool finFlag = false;
	};

	namespace internal
	{
		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return A negative value if seqNum1 < seqNum2, zero if equal, or a positive value if seqNum1 > seqNum2.
		int compareSeqNum(uint32_t seqNum1, uint32_t seqNum2);

		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return '-1' if seqNum1 < seqNum2, '0' if equal, or a '1' if seqNum1 > seqNum2.
		int compareSeqNumClamped(uint32_t seqNum1, uint32_t seqNum2);

		// Calculates the true sequence number with the extra pre-sequence padding.
		inline uint32_t calcTrueSeqNum(uint32_t seqNum, SeqFlags flags)
		{
			return seqNum + (flags.synFlag ? 1 : 0);
		};

		// Calculates the true next expected sequence number with the extra pre and post sequence padding.
		inline uint32_t calcNextSeqNum(uint32_t seqNum, size_t dataLen, SeqFlags flags)
		{
			return seqNum + dataLen + (flags.synFlag ? 1 : 0) + (flags.finFlag ? 1 : 0);
		};
	}  // namespace internal

	/*
	  In cases where out of order parts are received:
	  - If duplicated data is shared between part N and part N+1, part N will have its dataLen attribute trimmed
	  down, so the shared data is present only in part N+1.
	*/

	/// @brief Part of a sequential data stream. Used for Out-of-order resolution.
	struct StreamSeqPart
	{
		static constexpr uint32_t INVALID_PART_ID = -1;

		uint8_t const* data = nullptr;
		uint32_t dataLen = 0;
		uint32_t seqNum = 0;

		/// @brief The index of the next part in the chain. INVALID_PART_ID for no next part.
		/// @remarks Also used to indicate the next free part when the part is not in use.
		uint32_t nextId = INVALID_PART_ID;

		/// @brief The index of the prev part in the chain. INVALID_PART_ID for no prev part.
		uint32_t prevId = INVALID_PART_ID;

		/// @brief Additional flags related to the sequence part, such as SYN and FIN flags.
		SeqFlags seqFlags;

		/// @brief Calculates the true sequence number of the payload.
		uint32_t trueSeqNum() const
		{
			return seqNum + (seqFlags.synFlag ? 1 : 0);
		}

		/// @brief The expected next sequence number after the current part.
		uint32_t nextSeqNum() const
		{
			return trueSeqNum() + dataLen + (seqFlags.finFlag ? 1 : 0);
		}
	};

	class TcpByteStreamData
	{
	public:
		uint8_t const* m_Data;
		size_t dataLen = 0;
		size_t missingBytes = 0;
	};

	class TcpByteStream;

	class TcpOnDataReadyCallbackData
	{
	};

	class TcpReassemblyV2
	{
	public:
		bool reassemblePacket(Packet& packet);
		bool reassemblePacket(RawPacket& rawPacket);

	private:
	};

	/// @brief Represents a chain of sequential data parts from a TCP byte stream.
	///
	/// This class is used as an API to a user to access the reordered byte stream data.
	class TcpByteStreamDataChain
	{
	public:
	private:
	};

	/// @brief A class that handles a singular TCP byte stream reassembly.
	///
	/// The class provides an API for inserting newly received parts of the stream and a callback mechanism to notify
	/// the user when new in-order data is ready.
	class TcpByteStream
	{
	public:
		std::function<void(TcpByteStreamDataChain const& dataChain)> m_OnDataReadyCallback;

		/// @brief Inserts a new part into the stream. The part is defined by its sequence number and data length.
		///
		/// @param[in] seqNum The sequence number of the segment.
		/// Note that this includes the pre-sequence padding, meaning the true payload starts seqNum is "seqNum +
		/// seqNumExtra.preSeqNum".
		///
		/// @param[in] data A pointer to the data buffer containing the bytes of this part.
		/// @param[in] dataLen The length of the sequence part.
		/// @param[in] seqNumExtraLen An optional parameter that can be used to specify extra length used to
		/// calculate the logical end sequence number.
		void insertSeq(uint32_t seqNum, uint8_t const* data, size_t dataLen, SeqFlags flags = {})
		{
			PCPP_ASSERT(dataLen <= std::numeric_limits<uint32_t>::max(), "Fragment dataLen field is only 32bit wide.");

			int c = internal::compareSeqNum(seqNum, m_ExpectedSeqNum);
			uint32_t nextSeqNum = internal::calcNextSeqNum(seqNum, dataLen, flags);

			// Past OOS: The new part is before the next expected sequence number.
			//  - We haven't received it and it is filling missing data.
			//  - We have received it and this is a retransmission.
			//  - We have received it, but the part extends past the expected sequence number and contains new data.

			// Past OOS.B: The new part is before the next expected sequence number,
			// but it has data that fills after the expected sequence number.
			//
			// This can happen when we have received part of the data, and then we receive a retransmission of an
			// earlier part that overlaps with the data we have already received. In this case, we should trim the
			// overlapping part and only keep the new data that fills after the expected sequence number.
			if (c < 0)
			{
				PCPP_LOG_DEBUG("[BEHIND HEAD OF LINE]");
				
				// The difference between the next expected sequence and the end of this part.
				if (internal::compareSeqNum(nextSeqNum, m_ExpectedSeqNum) <= 0)
				{
					// FULL RETRANSMISSON:
					// The head of line is past the end of this segment. Ignore it.
					return;
				}

				// PARTIAL RETRANSMISSION:
				// The head of line is past the start of this segment, but before its end.
				// Trim the left of the segment to remove the stale part.
				// Keep the new part that fills after the head of line.

				data += m_ExpectedSeqNum - seqNum;
				dataLen = nextSeqNum - m_ExpectedSeqNum;
				seqNum = m_ExpectedSeqNum;
				flags.synFlag = false;  // Clear the SYN flag since we are trimming from the
			}

			// Good case: The new part is exactly the next expected sequence number.
			//  - Update the expected sequence number and send the data to the user.
			if (c <= 0)
			{
				// TODO: Send the data to the user.
				PCPP_LOG_DEBUG("[IN-ORDER] Received SEQ=" << seqNum << " with LEN=" << dataLen << " bytes. SYN="
				                                          << flags.synFlag << ";FIN=" << flags.finFlag << '\n');

				// Attempt to unlink any buffered out-of-order parts that would be in-order after the new part.
				uint32_t headId;
				auto* parts = tryUnlinkOrderedChainFromHead(m_ReorderList, nextSeqNum, &headId);

				StreamSeqPart tempPart;

				// If there are any buffered out-of-order parts that are now in-order, link them after the new part.
				// The linking is only forward link, due to inability to generate a valid PartID for the temporary
				// part representing the new in-order part.
				if (parts != nullptr)
				{
					tempPart.nextId = headId;
				}

				// TODO: Release the unlinked parts back to the free list.

				// TODO: Advance expected number and attempt to unblock out-of-order.
				m_ExpectedSeqNum = nextSeqNum;

				return;
			}

			// Future OOS: The new part is after the next expected sequence number.
			//  - We need to buffer it until the missing part(s) arrive.
			//  - We also need to try to merge with other Future OOS parts if they are contiguous.
			if (c > 0)
			{
				PCPP_LOG_DEBUG("[OOS] Received SEQ=" << seqNum << " with LEN=" << dataLen
				                                     << " bytes, but expected SEQ=" << m_ExpectedSeqNum
				                                     << ". SYN=" << flags.synFlag << ";FIN=" << flags.finFlag << '\n');
				insertSeqToReorderBuffer(seqNum, data, dataLen, flags);
			}
		}

		/// @brief Advances the expected sequence number by a given amount.
		///
		/// This is typically called if special rules need to be applied such as TCP SYN packets.
		///
		/// @param[in] seqNum The number of bytes to advance the expected sequence number by.
		void advanceSeq(uint32_t seqNum)
		{
			m_ExpectedSeqNum += seqNum;
		}

		uint32_t expectedSeq() const
		{
			return m_ExpectedSeqNum;
		}

		void reserveReorderBuffer(size_t numParts)
		{
			// Clamps the maximum buffer, as we can't store over UINT32_MAX parts due to the 32-bit part id fields.
			numParts = std::min(numParts, static_cast<size_t>(std::numeric_limits<uint32_t>::max()));
			m_Parts.reserve(numParts);
		}

	private:
		/// @brief Inserts a new part into the reorder buffer.
		///
		/// This is used for buffering out-of-order packets until the head of the stream reaches them.
		/// This method is meant to be used internally from insertSeq for out-of-order packets.
		///
		/// @param[in] seqNum The sequence number of the new part.
		/// @param[in] data A pointer to the data buffer containing the bytes of this part.
		/// @param[in] dataLen The length of the data buffer.
		/// @param[in] flags Flags related to the sequence part, such as SYN and FIN flags.
		void insertSeqToReorderBuffer(uint32_t seqNum, uint8_t const* data, size_t dataLen, SeqFlags flags);

		struct NodeIndexList
		{
			uint32_t head = StreamSeqPart::INVALID_PART_ID;
		};

		/// @brief Links a new node into the stream between the given previous and next nodes.
		///
		/// @param node The node to link.
		/// @param prev A node preceeding the new node in the stream, or null if the new node is the new head of the
		/// stream.
		/// @param next A node following the new node in the stream, or null if the new node is the new tail of the
		/// stream.
		void linkNode(NodeIndexList& list, StreamSeqPart* node, StreamSeqPart* prev, StreamSeqPart* next)
		{
			PCPP_ASSERT(node != nullptr, "Node to link cannot be null");
			PCPP_ASSERT(prev == nullptr || node != prev, "Node cannot be linked to itself as previous");
			PCPP_ASSERT(next == nullptr || node != next, "Node cannot be linked to itself as next");
			PCPP_ASSERT(prev == nullptr || next == nullptr || prev != next, "Prev and next cannot be the same node");

			PCPP_ASSERT(node->nextId == StreamSeqPart::INVALID_PART_ID &&
			                node->prevId == StreamSeqPart::INVALID_PART_ID,
			            "New node must be unlinked.");

			uint32_t nodeId = getPartIdSafe(node);
			uint32_t prevId = getPartIdSafe(prev);
			uint32_t nextId = getPartIdSafe(next);

			PCPP_ASSERT(nodeId != StreamSeqPart::INVALID_PART_ID, "Node must have a valid id");
			PCPP_ASSERT(prev == nullptr || prevId != StreamSeqPart::INVALID_PART_ID, "Prev must have a valid id");
			PCPP_ASSERT(next == nullptr || nextId != StreamSeqPart::INVALID_PART_ID, "Next must have a valid id");

			PCPP_ASSERT(prev != nullptr ||
			                ((next == nullptr && list.head == StreamSeqPart::INVALID_PART_ID) || nextId == list.head),
			            "A new head can only be assigned if the chain is empty or the next node is the current head");

			// Link the new part to its neighbors in the stream.
			if (prev != nullptr)
			{
				PCPP_ASSERT(next == nullptr || prev->nextId == nextId, "prev->next must be next's id");
				PCPP_ASSERT(next != nullptr || prev->nextId == StreamSeqPart::INVALID_PART_ID,
				            "prev->next must be invalid id");

				prev->nextId = nodeId;
				node->prevId = prevId;
			}
			else
			{
				// This means the new part is the new head of the stream.
				list.head = nodeId;
				node->prevId = StreamSeqPart::INVALID_PART_ID;
			}

			if (next != nullptr)
			{
				PCPP_ASSERT(prev == nullptr || next->prevId == prevId, "next->prevId must be prev's id");
				PCPP_ASSERT(prev != nullptr || next->prevId == StreamSeqPart::INVALID_PART_ID,
				            "next->prevId must be invalid id");

				next->prevId = nodeId;
				node->nextId = nextId;
			}
			else
			{
				node->nextId = StreamSeqPart::INVALID_PART_ID;
			}
		}

		/// @brief Inserts a chain of nodes into the list head, with the given node as the new head of the list.
		/// @param[in] list The list to insert the chain into. The head of the list will be updated to point to the head
		/// of the new chain.
		/// @param[in] chainHead The head node of the chain to insert.
		void insertChainAtHead(NodeIndexList& list, StreamSeqPart* chainHead)
		{
			PCPP_ASSERT(chainHead != nullptr, "Chain head cannot be null");
			PCPP_ASSERT(chainHead->prevId == StreamSeqPart::INVALID_PART_ID,
			            "Chain head must be unlinked from any previous nodes");

			uint32_t chainHeadId = getPartIdSafe(chainHead);
			PCPP_ASSERT(chainHeadId != StreamSeqPart::INVALID_PART_ID, "Chain head must have a valid id");

			StreamSeqPart* chainTail = chainHead;
			while (chainTail->nextId != StreamSeqPart::INVALID_PART_ID)
			{
				chainTail = getPartSafe(chainTail->nextId);
			}

			uint32_t oldHeadId = list.head;
			StreamSeqPart* oldHead = getPartSafe(list.head);

			chainTail->nextId = oldHeadId;
			oldHead->prevId = chainTail->prevId;

			list.head = chainHeadId;
			chainHead->prevId = StreamSeqPart::INVALID_PART_ID;
		}

		/// @brief Unlinks a node from a linked list, connecting its previous and next nodes together.
		/// @param[in] list The list the node belongs to.
		/// @param[in] node The node to unlink from the list. The node must be currently linked in the list.
		void unlinkNode(NodeIndexList& list, StreamSeqPart* node)
		{
			PCPP_ASSERT(node != nullptr, "Node to unlink cannot be null");

			uint32_t nodeId = getPartIdSafe(node);
			uint32_t prevId = node->prevId;
			uint32_t nextId = node->nextId;

			auto prev = getPartSafe(prevId);
			auto next = getPartSafe(nextId);

			PCPP_ASSERT(prev == nullptr || prev->nextId == nodeId, "prev->next must be node's id");
			PCPP_ASSERT(next == nullptr || next->prevId == nodeId, "next->prev must be node's id");

			if (prev != nullptr)
			{
				// Unlinking from prev node.
				prev->nextId = nextId;
			}
			else
			{
				// No prev node. Unlinking the head.
				PCPP_ASSERT(nodeId == list.head, "Node should be the head of the list since it has no prev");
				list.head = nextId;  // If nextId is invalid, this correctly sets the head to invalid as well.
			}

			if (next != nullptr)
			{
				// Unlinking from next node.
				next->prevId = prevId;
			}

			node->nextId = StreamSeqPart::INVALID_PART_ID;
			node->prevId = StreamSeqPart::INVALID_PART_ID;
		}

		/// @brief Attempt to unlink a chain of contiguous parts starting from the given sequence number.
		///
		/// This is the primary mechanism for unblocking the reorder buffer when new in-order data is received.
		///
		/// The function will check the head of the list for a part with the expected sequence number.
		/// If it finds such a part, it will unlink it and every contiguous part following it, until it reaches a part
		/// that is not contiguous with the previous one.
		///
		/// NOTE: The list must be ordered by sequence number, with the head being the part with the lowest sequence
		/// number. No overlapping sequence numbers can be present in the list.
		///
		/// @param[in] list The list to unlink the chain from. This is typically the reorder buffer list.
		/// @param[in] expectedSeqNum The expected sequence number of the head part.
		/// @param[out] headId An optional pointer to store the id of the head part of the unlinked chain.
		/// @return A pointer to the head of the unlinked chain, or null if the head part does not have the expected
		/// sequence number.
		StreamSeqPart* tryUnlinkOrderedChainFromHead(NodeIndexList& list, uint32_t expectedSeqNum,
		                                             uint32_t* headId = nullptr)
		{
			StreamSeqPart* head = getPartSafe(list.head);

			PCPP_ASSERT(head == nullptr, "The head part must be valid.");
			if (head == nullptr || internal::compareSeqNum(head->seqNum, expectedSeqNum) != 0)
			{
				// The head part does not have the expected sequence number, so we cannot unlink an ordered chain.
				return nullptr;
			}

			StreamSeqPart* current = head;
			StreamSeqPart* next = getPartSafe(current->nextId);

			while (next != nullptr && internal::compareSeqNum(current->nextSeqNum(), next->seqNum) == 0)
			{
				current = next;
				next = getPartSafe(current->nextId);
			}

			// Checks if the list is correctly ordered, with no overlaps and the head being the lowest sequence number.
			PCPP_ASSERT(next == nullptr || internal::compareSeqNum(current->nextSeqNum(), next->seqNum) < 0,
			            "If next part exists, it must be of higher sequence number.");

			// Unlink current from next, making current the new tail of the chain.
			uint32_t nextId = current->nextId;
			current->nextId = StreamSeqPart::INVALID_PART_ID;

			if (next != nullptr)
			{
				// We have another node left in the list.
				next->prevId = StreamSeqPart::INVALID_PART_ID;
			}

			// Store the head id if the caller wants it.
			if (headId != nullptr)
			{
				*headId = list.head;
			}

			list.head = nextId;  // If nextId is invalid, this correctly sets the head to invalid as well.
			return head;
		}

		StreamSeqPart* getPartSafe(uint32_t partId)
		{
			if (partId == StreamSeqPart::INVALID_PART_ID)
			{
				return nullptr;
			}

			PCPP_ASSERT(partId < m_Parts.size(), "Accessing invalid part");
			return &m_Parts[partId];
		}

		uint32_t getPartIdSafe(StreamSeqPart const* part) const
		{
			if (part == nullptr)
			{
				return StreamSeqPart::INVALID_PART_ID;
			}

			auto partId = part - &m_Parts[0];
			PCPP_ASSERT(partId > 0 && partId < m_Parts.size(), "Part pointer is out of range of the parts vector");
			return partId;
		}

		StreamSeqPart* getFreePart()
		{
			if (m_FreeSlotsList.head == StreamSeqPart::INVALID_PART_ID)
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
			StreamSeqPart* newPart = nullptr;
			newPart = &m_Parts[m_FreeSlotsList.head];

			// When parts are not in use, they are linked together with other free parts using the nextId
			// attribute. This makes the logical free list of parts, and allows us to reuse parts without
			// having to search for them or maintain a separate free list.
			m_FreeSlotsList.head = newPart->nextId;
			newPart->nextId = StreamSeqPart::INVALID_PART_ID;
			newPart->prevId = StreamSeqPart::INVALID_PART_ID;
			return newPart;
		}

		StreamSeqPart* returnFreePart(StreamSeqPart* part)
		{
			PCPP_ASSERT(part != nullptr, "Returned part cannot be null");

			uint32_t partId = getPartIdSafe(part);
			PCPP_ASSERT(partId < m_Parts.size(), "Returned part id is out of range of the parts vector");

			// When parts are not in use, they are linked together with other free parts using the nextId
			// attribute. This makes the logical free list of parts, and allows us to reuse parts without
			// having to search for them or maintain a separate free list.

			linkNode(m_FreeSlotsList, part, nullptr, getPartSafe(m_FreeSlotsList.head));
			return part;
		}

	private:
		std::vector<StreamSeqPart> m_Parts;

		/// @brief The index of the first part in the out-of-order stream.
		///
		/// This is the part with the sequence number closest to the expected sequence number, and is the first part
		/// that should be checked for merging when a new part is inserted.
		NodeIndexList m_ReorderList;
		NodeIndexList m_FreeSlotsList;

		uint32_t m_ExpectedSeqNum = 0;
	};
}  // namespace pcpp