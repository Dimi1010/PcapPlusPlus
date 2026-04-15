#include "TcpReassemblyNext.h"

namespace
{

}

namespace pcpp
{
	namespace internal
	{
		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return A negative value if seqNum1 < seqNum2, zero if equal, or a positive value if seqNum1 > seqNum2.
		int compareSeqNum(uint32_t seqNum1, uint32_t seqNum2)
		{
			return seqNum1 - seqNum2;
		}

		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return '-1' if seqNum1 < seqNum2, '0' if equal, or a '1' if seqNum1 > seqNum2.
		int compareSeqNumClamped(uint32_t seqNum1, uint32_t seqNum2)
		{
			auto c = compareSeqNum(seqNum1, seqNum2);
			return c < 0 ? -1 : c > 0 ? 1 : 0;
		}
	}  // namespace internal

	void TcpByteStream::insertSeqToReorderBuffer(uint32_t seqNum, uint8_t const* data, size_t dataLen, SeqFlags flags)
	{
		uint32_t nextSeqNum = internal::calcNextSeqNum(seqNum, dataLen, flags);

		// TODO: Attempt to merge with other OOS parts if they are contiguous.
		// If the new part is not contiguous with any existing OOS part, we can simply add it as a new part
		// in the stream.

		auto* firstPart = getPartSafe(m_ReorderList.head);
		if (firstPart == nullptr)
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
			return;
		}

		// We have at least one part in the reorder buffer.
		// Insert the new part into the reorder buffer and link it to its closest neighbors in the stream.
		PCPP_ASSERT(firstPart != nullptr, "Reorder buffer should not be empty");

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
}  // namespace pcpp