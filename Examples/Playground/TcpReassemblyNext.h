#pragma once

#define NOMINMAX

#include <iostream>
#include "TcpReassembly.h"
#include "AssertionUtils.h"
#include "PacketUtils.h"

#define PCPP_LOG_DEBUG(m) std::cerr << m << '\n';

namespace pcpp
{
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
	}  // namespace internal

	/*
	  In cases where out of order parts are received:
	  - If duplicated data is shared between part N and part N+1, part N will have its dataLen attribute trimmed
	  down, so the shared data is present only in part N+1.
	*/

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

	class SequenceByteStream
	{
	public:
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

			// Calculates the true sequence number with the extra pre-sequence padding.
			auto calcTrueSeqNum = [](uint32_t seqNum, SeqFlags flags) { return seqNum + (flags.synFlag ? 1 : 0); };

			// Calculates the true next expected sequence number with the extra pre and post sequence padding.
			auto calcNextSeqNum = [](uint32_t seqNum, size_t dataLen, SeqFlags flags) {
				return seqNum + dataLen + (flags.synFlag ? 1 : 0) + (flags.finFlag ? 1 : 0);
			};

			// Good case: The new part is exactly the next expected sequence number.
			//  - Update the expected sequence number and send the data to the user.
			int c = internal::compareSeqNum(seqNum, m_ExpectedSeqNum);
			uint32_t nextSeqNum = calcNextSeqNum(seqNum, dataLen, flags);

			if (c == 0)
			{
				// TODO: Send the data to the user.
				PCPP_LOG_DEBUG("[IN-ORDER] Received SEQ=" << seqNum << " with LEN=" << dataLen << " bytes. SYN="
				                                          << flags.synFlag << ";FIN=" << flags.finFlag << '\n');

				// TODO: Advance expected number and attempt to unblock out-of-order.
				m_ExpectedSeqNum = nextSeqNum;

				return;
			}

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
				PCPP_LOG_DEBUG("[RTX] Received SEQ=" << seqNum << " with LEN=" << dataLen
				                                     << " bytes, but it fills after expected SEQ=" << m_ExpectedSeqNum
				                                     << ". SYN=" << flags.synFlag << ";FIN=" << flags.finFlag << '\n');

				// The difference between the next expected sequence and the end of this part.
				// Also the length of the new data that is not overlapping with the already received data.
				auto newSeqDiff = internal::compareSeqNum(nextSeqNum, m_ExpectedSeqNum);
				if (newSeqDiff > 0)
				{
					// TODO: Trim the overlapping part and send the new data to the user.
					PCPP_LOG_DEBUG("[RTX] SEQ=" << seqNum << " with LEN=" << dataLen << " contains new data");

					auto newData = data + (m_ExpectedSeqNum - seqNum);
					auto newDataLen = newSeqDiff;

					// TODO: Attempt to merge with other OOS parts.
					m_ExpectedSeqNum = nextSeqNum;
				}

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

				// TODO: Insert the part into the OOS buffer and link to the nearest parts in the stream.
				// TODO: Attempt to merge with other OOS parts if they are contiguous.
				// If the new part is not contiguous with any existing OOS part, we can simply add it as a new part
				// in the stream.

				// StreamSeqPart* newPart = getFreePart();

				// Populate the new part.

				// Types of overlap between newP and p[N]:
				//
				// Legend: [n ... n] = new segment range, {p ... p} = existing part range
				//
				// Overlap cases between new segment (n) and existing part p[N]:
				//
				// 1. Left overlap (n starts before p, ends inside p):
				//    [n ----{p--- n] -----p}
				//
				//    Trim the new part to remove the overlapping part, and link it before p.
				//
				// 2. Right overlap (n starts inside p, ends after p):
				//    {p ----[n--- p} -----n]
				//
				//    Trim p to remove the overlapping part, and link n after p.
				//
				// 3. n envelops p (n starts before and ends after p):
				//    [n ---{p------p}--- n]
				//
				//    Possibly replace p with n, and free n.
				//
				// 4. p envelops n (n is fully inside p):
				//    {p ---[n------n]--- p}
				//
				//    Segment n is fully redundant; discard it.
				//
				//
				// Overlap cases between new segment (n) and existing part p[N + 1] after overlap with p[N]:
				//
				// a

				// Insert the new part into the reorder buffer and link it to its closest neighbors in the stream.
				auto* firstPart = getPartSafe(m_ReorderList.head);
				if (firstPart != nullptr)
				{
					StreamSeqPart* nextPart = firstPart;
					StreamSeqPart* prevPart = nullptr;

					// Find the first part that starts after or at the sequence number of the new part, if any.
					while (nextPart != nullptr && internal::compareSeqNum(nextPart->seqNum, seqNum) < 0)
					{
						prevPart = nextPart;
						nextPart = getPartSafe(nextPart->nextId);
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
							PCPP_ASSERT(nextSeqNum == calcNextSeqNum(seqNum, dataLen, flags),
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

							size_t trimLen = nextPart->seqNum - calcTrueSeqNum(seqNum, flags);
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
								uint32_t offset = nextPart->nextSeqNum() - calcTrueSeqNum(seqNum, flags);
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
									uint32_t prevId = getPartIdSafe(prevPart);
									uint32_t nextId = getPartIdSafe(nextPart);

									// Add the new part to the OOS buffer and link it to its neighbors.
									StreamSeqPart* newPart = getFreePart();
									uint32_t newId = getPartIdSafe(newPart);

									// Restore the pointers after possible reallocation.
									prevPart = getPartSafe(prevId);
									nextPart = getPartSafe(nextId);

									// Populate the new node.
									newPart->data = data;
									newPart->dataLen = trimLen;
									newPart->seqNum = seqNum;
									newPart->seqFlags = trimFlags;

									PCPP_ASSERT(newPart->dataLen > 0, "Adding 0 data sequence is pointless.");

									// Link the new node.
									linkNode(m_ReorderList, newPart, prevPart, nextPart);
								}

								// Advance parts and redo check.
								prevPart = nextPart;
								nextPart = getPartSafe(nextPart->nextId);

								data = exData;
								dataLen = exDataLen;
								seqNum = exDataSeq;
								flags = exFlags;

								PCPP_ASSERT(nextSeqNum == calcNextSeqNum(seqNum, dataLen, flags),
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
					uint32_t prevId = getPartIdSafe(prevPart);
					uint32_t nextId = getPartIdSafe(nextPart);

					// Add the new part to the OOS buffer and link it to its neighbors.
					StreamSeqPart* newPart = getFreePart();
					uint32_t newId = getPartIdSafe(newPart);

					// Restore the pointers after possible reallocation.
					prevPart = getPartSafe(prevId);
					nextPart = getPartSafe(nextId);

					// Populate the new node.

					newPart->data = data;
					newPart->dataLen = dataLen;
					newPart->seqNum = seqNum;
					newPart->seqFlags = flags;

					// TODO Edge: If a SYN or FIN flag is added without data, possibly merge it to a nearby fragment.
					PCPP_ASSERT(newPart->dataLen > 0, "Adding 0 data sequence is pointless.");

					linkNode(m_ReorderList, newPart, prevPart, nextPart);
				}
				else
				{
					// The reorder buffer is empty.
					// Create a new part and fill it.

					StreamSeqPart* newPart = getFreePart();
					PCPP_ASSERT(newPart != nullptr, "Failed to get free part from the pool");
					uint32_t index = getPartIdSafe(newPart);

					newPart->data = data;
					newPart->dataLen = dataLen;
					newPart->seqNum = seqNum;
					newPart->seqFlags = flags;

					// First node, no other nodes to link to.
					linkNode(m_ReorderList, newPart, nullptr, nullptr);
				}

				// TODO: Handle FIN or RST?
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