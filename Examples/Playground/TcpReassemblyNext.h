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
	struct TcpStreamSeqPart
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

	namespace internal
	{

	}

	/// @brief A class that handles a singular unidirectional TCP byte stream reassembly.
	///
	/// The class provides an API for inserting newly received parts of the stream and a callback mechanism to notify
	/// the user when new in-order data is ready.
	class TcpByteStream
	{
	public:
		/// @brief Inserts a new part into the stream. The part is defined by its sequence number and data length.
		///
		/// @param[in] seqNum The sequence number of the segment.
		/// Note that this includes the pre-sequence padding, meaning the true payload starts seqNum is "seqNum +
		/// seqNumExtra.preSeqNum".
		///
		/// @tparam OnDataReadyCallback
		/// @param[in] onDataReady A callback function that is invoked when new in-order data is ready.
		/// @param[in] data A pointer to the data buffer containing the bytes of this part.
		/// @param[in] dataLen The length of the sequence part.
		/// @param[in] seqNumExtraLen An optional parameter that can be used to specify extra length used to
		/// calculate the logical end sequence number.
		template <typename OnDataReadyCallback>
		void insertSeq(OnDataReadyCallback onDataReady, uint32_t seqNum, uint8_t const* data, size_t dataLen,
		               SeqFlags flags = {})
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

			// In-Order packet or post-trimmed Past OOS.B.
			// Good case: The new part is exactly the next expected sequence number.
			//  - Update the expected sequence number and send the data to the user.
			if (c <= 0)
			{
				PCPP_LOG_DEBUG("[IN-ORDER] Received SEQ=" << seqNum << " with LEN=" << dataLen << " bytes. SYN="
				                                          << flags.synFlag << ";FIN=" << flags.finFlag << '\n');

				// TODO: Handle the case where the new part overlaps with the buffered out-of-order parts.
				// Both the pre-first part overlap, and post-last part overlap.

				// Attempt to unlink any buffered out-of-order parts that would be in-order after the new part.
				uint32_t headId;
				auto* parts = tryPopContinuousChain(m_ReorderList, nextSeqNum, &headId);

				TcpStreamSeqPart tempPart;

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

		/// @brief Flushes all buffered out-of-order parts, until the head of line blocks again, using the given
		/// sequence number as the new reference to unblock on.
		///
		/// This is typically called if ACK packet was received on the oposite line, which means the peer has received
		/// all the data up to the ACK sequence number. In that case we can advance the head of line to the ACK sequence
		/// number since there won't be any retransmissions of packet before the ACK sequence number.
		///
		/// @tparam OnDataReadyCallback A callback that takes a reference to a TcpByteStreamDataChain representing the
		/// newly unblocked in-order data, and is called for any data parts that are unblocked as a result of this
		/// operation.
		///
		/// @param[in] seqNum The sequence number to reset to.
		/// @param[in] callback A callback to call for any data parts that are unblocked as a result of this operation.
		template <typename OnDataReadyCallback> void flushAllUntilSeq(uint32_t seqNum, OnDataReadyCallback callback)
		{
			// Flush all the buffered out-of-order parts, until the head of line blocks again.
			// Use the new seqNum as the reference to unblock on.

			// Pops all parts that are prior to the new seqNum.
			uint32_t headId;
			auto* parts = tryPopChainFrom(m_ReorderList, seqNum, &headId);
			if (parts == nullptr)
			{
				m_ExpectedSeqNum = seqNum;
				return;
			}

			// TODO: Unlink any buffered out-of-order parts that would be left behind the new head of line.
			// Call callback with missing data indication for the unlinked parts, if needed.
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
			uint32_t head = TcpStreamSeqPart::INVALID_PART_ID;
		};

		/// @brief Links a new node into the stream between the given previous and next nodes.
		///
		/// @param node The node to link.
		/// @param prev A node preceeding the new node in the stream, or null if the new node is the new head of the
		/// stream.
		/// @param next A node following the new node in the stream, or null if the new node is the new tail of the
		/// stream.
		void linkNode(NodeIndexList& list, TcpStreamSeqPart* node, TcpStreamSeqPart* prev, TcpStreamSeqPart* next)
		{
			PCPP_ASSERT(node != nullptr, "Node to link cannot be null");
			PCPP_ASSERT(prev == nullptr || node != prev, "Node cannot be linked to itself as previous");
			PCPP_ASSERT(next == nullptr || node != next, "Node cannot be linked to itself as next");
			PCPP_ASSERT(prev == nullptr || next == nullptr || prev != next, "Prev and next cannot be the same node");

			PCPP_ASSERT(node->nextId == TcpStreamSeqPart::INVALID_PART_ID &&
			                node->prevId == TcpStreamSeqPart::INVALID_PART_ID,
			            "New node must be unlinked.");

			uint32_t nodeId = getPartIdSafe(node);
			uint32_t prevId = getPartIdSafe(prev);
			uint32_t nextId = getPartIdSafe(next);

			PCPP_ASSERT(nodeId != TcpStreamSeqPart::INVALID_PART_ID, "Node must have a valid id");
			PCPP_ASSERT(prev == nullptr || prevId != TcpStreamSeqPart::INVALID_PART_ID, "Prev must have a valid id");
			PCPP_ASSERT(next == nullptr || nextId != TcpStreamSeqPart::INVALID_PART_ID, "Next must have a valid id");

			PCPP_ASSERT(prev != nullptr || ((next == nullptr && list.head == TcpStreamSeqPart::INVALID_PART_ID) ||
			                                nextId == list.head),
			            "A new head can only be assigned if the chain is empty or the next node is the current head");

			// Link the new part to its neighbors in the stream.
			if (prev != nullptr)
			{
				PCPP_ASSERT(next == nullptr || prev->nextId == nextId, "prev->next must be next's id");
				PCPP_ASSERT(next != nullptr || prev->nextId == TcpStreamSeqPart::INVALID_PART_ID,
				            "prev->next must be invalid id");

				prev->nextId = nodeId;
				node->prevId = prevId;
			}
			else
			{
				// This means the new part is the new head of the stream.
				list.head = nodeId;
				node->prevId = TcpStreamSeqPart::INVALID_PART_ID;
			}

			if (next != nullptr)
			{
				PCPP_ASSERT(prev == nullptr || next->prevId == prevId, "next->prevId must be prev's id");
				PCPP_ASSERT(prev != nullptr || next->prevId == TcpStreamSeqPart::INVALID_PART_ID,
				            "next->prevId must be invalid id");

				next->prevId = nodeId;
				node->nextId = nextId;
			}
			else
			{
				node->nextId = TcpStreamSeqPart::INVALID_PART_ID;
			}
		}

		/// @brief Inserts a chain of nodes into the list head, with the given node as the new head of the list.
		/// @param[in] list The list to insert the chain into. The head of the list will be updated to point to the head
		/// of the new chain.
		/// @param[in] chainHead The head node of the chain to insert.
		void insertChainAtHead(NodeIndexList& list, TcpStreamSeqPart* chainHead)
		{
			PCPP_ASSERT(chainHead != nullptr, "Chain head cannot be null");
			PCPP_ASSERT(chainHead->prevId == TcpStreamSeqPart::INVALID_PART_ID,
			            "Chain head must be unlinked from any previous nodes");

			uint32_t chainHeadId = getPartIdSafe(chainHead);
			PCPP_ASSERT(chainHeadId != TcpStreamSeqPart::INVALID_PART_ID, "Chain head must have a valid id");

			TcpStreamSeqPart* chainTail = chainHead;
			while (chainTail->nextId != TcpStreamSeqPart::INVALID_PART_ID)
			{
				chainTail = getPartSafe(chainTail->nextId);
			}

			uint32_t oldHeadId = list.head;
			TcpStreamSeqPart* oldHead = getPartSafe(list.head);

			chainTail->nextId = oldHeadId;
			oldHead->prevId = chainTail->prevId;

			list.head = chainHeadId;
			chainHead->prevId = TcpStreamSeqPart::INVALID_PART_ID;
		}

		/// @brief Unlinks a node from a linked list, connecting its previous and next nodes together.
		/// @param[in] list The list the node belongs to.
		/// @param[in] node The node to unlink from the list. The node must be currently linked in the list.
		void unlinkNode(NodeIndexList& list, TcpStreamSeqPart* node)
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

			node->nextId = TcpStreamSeqPart::INVALID_PART_ID;
			node->prevId = TcpStreamSeqPart::INVALID_PART_ID;
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
		/// @param[in] expSeqNum The expected sequence number of the head part.
		/// @param[out] headId An optional pointer to store the id of the head part of the unlinked chain.
		/// @return A pointer to the head of the unlinked chain, or null if the head part does not have the expected
		/// sequence number.
		TcpStreamSeqPart* tryPopContinuousChain(NodeIndexList& list, uint32_t expSeqNum, uint32_t* headId = nullptr);

		/// @brief Attempt to unblock a chain to a given sequence number.
		///
		/// All parts starting from the head of reorder buffer until the first part that is not contiguous after the
		/// reference sequence number will be returned as a chain.
		///
		/// This function is useful for flushing the reorder buffer until a given sequence number combined with
		/// consuming as much of the reorder buffer afterwards as possible.
		///
		/// This is commonly used when an ACK is received on the opposite line. The sequence up to ACK is flushed
		/// as is, along with missing data markers. All contiguous parts after the ACK sequence number are also flushed
		/// as they are now unblocked.
		///
		/// @param list The list to unlink the chain from. This is typically the reorder buffer list.
		/// @param refSeqNum A reference sequence number to unblock to. This is typically the ACK number.
		/// @param headId An optional pointer to store the id of the head part of the unlinked chain.
		/// @return A pointer to the head of the unlinked chain, or null if the operation did not unblock any parts.
		TcpStreamSeqPart* tryPopChainFrom(NodeIndexList& list, uint32_t refSeqNum, uint32_t* headId = nullptr);

		TcpStreamSeqPart* getPartSafe(uint32_t partId)
		{
			if (partId == TcpStreamSeqPart::INVALID_PART_ID)
			{
				return nullptr;
			}

			PCPP_ASSERT(partId < m_Parts.size(), "Accessing invalid part");
			return &m_Parts[partId];
		}

		uint32_t getPartIdSafe(TcpStreamSeqPart const* part) const
		{
			if (part == nullptr)
			{
				return TcpStreamSeqPart::INVALID_PART_ID;
			}

			auto partId = part - &m_Parts[0];
			PCPP_ASSERT(partId > 0 && partId < m_Parts.size(), "Part pointer is out of range of the parts vector");
			return partId;
		}

		TcpStreamSeqPart* getFreePart()
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

		TcpStreamSeqPart* returnFreePart(TcpStreamSeqPart* part)
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
		std::vector<TcpStreamSeqPart> m_Parts;

		/// @brief The index of the first part in the out-of-order stream.
		///
		/// This is the part with the sequence number closest to the expected sequence number, and is the first part
		/// that should be checked for merging when a new part is inserted.
		NodeIndexList m_ReorderList;
		NodeIndexList m_FreeSlotsList;

		uint32_t m_ExpectedSeqNum = 0;
	};

	/// @brief Represents a chain of sequential data parts from a TCP byte stream.
	///
	/// This class is used as an API to a user to access the reordered byte stream data.
	class TcpByteStreamDataChain
	{
	public:
	private:
	};

	class TcpReassemblyV2
	{
	public:
		enum class ConnectionEndReason
		{
			FinPacket,
			RstPacket,
			UserClosed,
		};

		class TcpMessageReadyCtx
		{
		};

		class TcpConnectionStartCtx
		{
		};

		class TcpConnectionEndCtx
		{
		};

		/// @typedef OnTcpMessageReady
		/// A callback invoked when new data arrives on a connection
		/// @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where
		/// 0 is the first side seen in the connection and 1 is the second side seen
		/// @param[in] tcpData The TCP data itself + connection information
		/// @param[in] ctx A context object.
		using OnTcpMessageReady =
		    std::function<void(int8_t side, const TcpByteStreamDataChain& tcpData, TcpMessageReadyCtx& ctx)>;

		/// @typedef OnTcpConnectionStart
		/// A callback invoked when a new TCP connection is identified (whether it begins with a SYN packet or not)
		/// @param[in] connectionData Connection information
		/// @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or nullptr if no
		/// cookie provided)

		/// @brief A callback invoked when a new TCP connection is identified.
		///
		/// The new connection may or may not begin with a SYN packet, depending on when the reassembly engine
		/// identifies the connection.
		/// 
		/// @param[in] connectionData
		/// @param[in] ctx
		using OnTcpConnectionStart =
		    std::function<void(const ConnectionData& connectionData, TcpConnectionStartCtx& ctx)>;

		/// @brief A callback invoked when a TCP connection is terminated.
		///
		/// The connection may be terminated either by a FIN or RST packet, or manually by the user.
		///
		/// @param[in] connectionData The connection info for the connection that is being terminated.
		/// @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user.
		/// @param[in] ctx
		using OnTcpConnectionEnd = std::function<void(const ConnectionData& connectionData, ConnectionEndReason reason,
		                                              TcpConnectionEndCtx& ctx)>;

		/// @brief A unique identifier for a TCP flow, used for tracking and reassembly.
		using FlowKey = uint32_t;

		using ReassemblyStatus = TcpReassembly::ReassemblyStatus;

		enum class ConnectionState
		{
			NotFound,
			Established,
			Closed,
		};

		ReassemblyStatus reassemblePacket(Packet& packet);
		ReassemblyStatus reassemblePacket(RawPacket& rawPacket);

		ConnectionState getConnectionState(FlowKey flowKey) const;

		void closeConnection(FlowKey flowKey);
		void closeAllConnections();

		uint32_t purgeClosedConnections(uint32_t maxCount = 0);

	private:
		struct Config
		{
		};

		struct TcpConnectionSide
		{
			TcpByteStream stream;
			uint16_t srcPort = 0;
			IPAddress srcIP;
		};

		struct TcpConnection
		{
			ConnectionData connectionData;
			std::array<TcpConnectionSide, 2> side;
			int8_t openStreamSides = 0;
		};

		using ConnectionMap = std::unordered_map<FlowKey, TcpConnection>;
		// using ConnectionInfoMap = std::unordered_map<FlowKey, ConnectionData>;

		Config m_Config;
		ConnectionMap m_Connections;
	};
}  // namespace pcpp