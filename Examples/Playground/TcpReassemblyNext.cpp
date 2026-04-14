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
	}
}  // namespace pcpp