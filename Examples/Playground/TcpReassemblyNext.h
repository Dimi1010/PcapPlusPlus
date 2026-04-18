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
		inline int compareSeqNum(uint32_t seqNum1, uint32_t seqNum2)
		{
			return seqNum1 - seqNum2;
		}

		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return '-1' if seqNum1 < seqNum2, '0' if equal, or a '1' if seqNum1 > seqNum2.
		inline int compareSeqNumClamped(uint32_t seqNum1, uint32_t seqNum2)
		{
			auto c = compareSeqNum(seqNum1, seqNum2);
			return c < 0 ? -1 : c > 0 ? 1 : 0;
		}

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

		/// @brief Part of a sequential data stream. Used for Out-of-order resolution.
		struct TcpStreamSeqPart
		{
			using PartId = uint32_t;

			static constexpr PartId INVALID_PART_ID = -1;

			uint8_t const* data = nullptr;
			uint32_t dataLen = 0;
			uint32_t seqNum = 0;

			/// @brief The index of the next part in the chain. INVALID_PART_ID for no next part.
			/// @remarks Also used to indicate the next free part when the part is not in use.
			PartId nextId = INVALID_PART_ID;

			/// @brief The index of the prev part in the chain. INVALID_PART_ID for no prev part.
			PartId prevId = INVALID_PART_ID;

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

		/// @brief A non-owning view over parts of a TCP byte stream.
		///
		/// This class provides API for iterating over partial buffers of a TCP byte stream, which may be non-contiguous
		/// in memory due to out-of-order segment arrival.
		class TcpByteStreamView
		{
		public:
#pragma region Iterators
			class Iterator
			{
			public:
				using iterator_category = std::forward_iterator_tag;
				using value_type = TcpStreamSeqPart const;
				using difference_type = std::ptrdiff_t;
				using pointer = TcpStreamSeqPart const*;
				using reference = TcpStreamSeqPart const&;

				Iterator() : m_View(nullptr), m_Current(nullptr)
				{}

				Iterator(TcpByteStreamView const* view, TcpStreamSeqPart const* current)
				    : m_View(view), m_Current(current)
				{}

				reference operator*() const
				{
					return *m_Current;
				}
				pointer operator->() const
				{
					return m_Current;
				}

				Iterator& operator++()
				{
					m_Current = m_View->getNextPart(m_Current);
					return *this;
				}

				Iterator operator++(int)
				{
					Iterator tmp = *this;
					++(*this);
					return tmp;
				}

				bool operator==(Iterator const& other) const
				{
					return m_Current == other.m_Current;
				}
				bool operator!=(Iterator const& other) const
				{
					return !(*this == other);
				}

			private:
				TcpByteStreamView const* m_View;
				TcpStreamSeqPart const* m_Current;
			};
#pragma endregion Iterators

			TcpByteStreamView(TcpStreamSeqPart head, std::vector<TcpStreamSeqPart> const& buffer)
			    : TcpByteStreamView(std::move(head), ScalarBuffer<TcpStreamSeqPart const>{
			                                             buffer.size() > 0 ? buffer.data() : nullptr, buffer.size() })
			{}

			TcpByteStreamView(TcpStreamSeqPart head, ScalarBuffer<TcpStreamSeqPart const> partsBuffer)
			    : m_FirstPart(std::move(head)), m_PartsBuffer(std::move(partsBuffer))
			{}

			TcpStreamSeqPart const* getFirstPart() const
			{
				return &m_FirstPart;
			}

			TcpStreamSeqPart const* getNextPart(TcpStreamSeqPart const* part) const
			{
				if (part->nextId == TcpStreamSeqPart::INVALID_PART_ID)
				{
					return nullptr;
				}

				PCPP_ASSERT(part->nextId < m_PartsBuffer.len, "Part out of bounds");
				if (part->nextId >= m_PartsBuffer.len)
				{
					return nullptr;
				}

				auto* ptr = m_PartsBuffer.buffer + part->nextId;
				return ptr;
			}

			Iterator begin() const
			{
				return Iterator(this, getFirstPart());
			}

			Iterator end() const
			{
				return Iterator(this, nullptr);
			}

		private:
			TcpStreamSeqPart m_FirstPart;
			ScalarBuffer<TcpStreamSeqPart const> m_PartsBuffer;
		};

		/// @brief A class that handles a singular unidirectional TCP byte stream reassembly.
		///
		/// The class provides an API for inserting newly received parts of the stream and a callback mechanism to
		/// notify the user when new in-order data is ready.
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
				PCPP_ASSERT(dataLen <= std::numeric_limits<uint32_t>::max(),
				            "Fragment dataLen field is only 32bit wide.");

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
					auto result = tryUnblockHeadOfLine(m_ReorderList, nextSeqNum);

					TcpStreamSeqPart tempPart;
					tempPart.data = data;
					tempPart.dataLen = dataLen;
					tempPart.seqNum = seqNum;
					tempPart.seqFlags = flags;

					// If there are any buffered out-of-order parts that are now in-order, link them after the new part.
					// The linking is only forward link, due to inability to generate a valid PartID for the temporary
					// part representing the new in-order part.

					uint32_t nextExpectedSeqNum;
					if (result.head != nullptr)
					{
						tempPart.nextId = result.headId;
						nextExpectedSeqNum = result.tail->nextSeqNum();
					}
					else
					{
						nextExpectedSeqNum = nextSeqNum;
					}

					// Construct a view over the ordered parts and send it to the callback.
					TcpByteStreamView view(tempPart, m_Parts);
					onDataReady(view);

					// TODO: Release the unlinked parts back to the free list.

					// Update the head of line to the next expected sequence number.
					// That being the end of the unblocked chain of in-order parts.
					m_ExpectedSeqNum = nextExpectedSeqNum;
					return;
				}

				// Future OOS: The new part is after the next expected sequence number.
				//  - We need to buffer it until the missing part(s) arrive.
				//  - We also need to try to merge with other Future OOS parts if they are contiguous.
				if (c > 0)
				{
					PCPP_LOG_DEBUG("[OOS] Received SEQ=" << seqNum << " with LEN=" << dataLen
					                                     << " bytes, but expected SEQ=" << m_ExpectedSeqNum << ". SYN="
					                                     << flags.synFlag << ";FIN=" << flags.finFlag << '\n');
					insertSeqToReorderBuffer(seqNum, data, dataLen, flags);
				}
			}

			/// @brief Sets the head of line to the given sequence number and flushes any buffered out-of-order parts
			/// that are now after head of line or in-order as a result.
			///
			/// This is typically called if ACK packet was received on the oposite line, which means the peer has
			/// received all the data up to the ACK sequence number. In that case we can advance the head of line to the
			/// ACK sequence number since there won't be any retransmissions of packet before the ACK sequence number.
			///
			/// The operation may advance the head of line further than the given sequence number if there are buffered
			/// out-of-order parts that are now in-order as a result.
			///
			/// @tparam OnDataReadyCallback A callback that takes a reference to a TcpByteStreamDataChain representing
			/// the newly unblocked in-order data, and is called for any data parts that are unblocked as a result of
			/// this operation.
			///
			/// @param[in] seqNum The sequence number to use as new head of line.
			/// @param[in] onDataReady A callback to call for any data parts that are unblocked as a result of this
			/// operation.
			template <typename OnDataReadyCallback>
			void setSeqHeadAndFlush(uint32_t seqNum, OnDataReadyCallback onDataReady)
			{
				// Flush all the buffered out-of-order parts, until the head of line blocks again.
				// Use the new seqNum as the reference to unblock on.

				// Pops all parts that are prior to the new seqNum.
				uint32_t headId;
				uint32_t nextSeqNum;
				auto result = forceUnblockHeadOfLineTo(m_ReorderList, seqNum);
				if (result.head == nullptr)
				{
					m_ExpectedSeqNum = seqNum;
					return;
				}

				TcpByteStreamView view(*result.head, m_Parts);
				onDataReady(view);

				returnFreePartRange(result.head, result.tail);

				m_ExpectedSeqNum = nextSeqNum;
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

			using PartId = TcpStreamSeqPart::PartId;
#pragma region Buffered Parts Indexing
			/// @brief Get a pointer to a part by its id. Returns nullptr if the partId is invalid.
			/// @param[in] partId The id of the part to get.
			/// @return A pointer to the part with the given id, or nullptr if the partId is invalid.
			TcpStreamSeqPart* getPart(PartId partId);

			/// @brief Get the id of a part from its pointer. Returns INVALID_PART_ID if the part pointer is null.
			///
			/// The pointer MUST BE a pointer to an element of the m_Parts vector or nullptr.
			///
			/// @param[in] part A pointer to the part.
			/// @return The id of the part, or INVALID_PART_ID if the part pointer is null.
			PartId getPartId(TcpStreamSeqPart const* part) const;
#pragma endregion

#pragma region Intrusive Index List API
			struct NodeIndexList
			{
				PartId head = TcpStreamSeqPart::INVALID_PART_ID;
			};

			/// @brief Insert a new node into the list after a given previous node.
			///
			/// See the overload that takes a previous node pointer for details.
			void insertNodeAfter(NodeIndexList& list, TcpStreamSeqPart::PartId prevId, TcpStreamSeqPart* newNode);

			/// @brief Insert a new node into the list after a given previous node.
			///
			/// If the previous node is null, the new node is inserted at the head of the list.
			/// Otherwise it is inserted after the previous node.
			///
			/// @param[in] list The list to insert the new node into.
			/// @param[in] prevNode The previous node to insert after, or null to insert at the head of the list.
			/// @param[in] newNode The new node to insert. Must not be linked in any list.
			void insertNodeAfter(NodeIndexList& list, TcpStreamSeqPart* prevNode, TcpStreamSeqPart* newNode);

			// void insertNodeBefore(NodeIndexList& list, TcpStreamSeqPart* newNode, TcpStreamSeqPart::PartId nextId);
			// void insertNodeBefore(NodeIndexList& list, TcpStreamSeqPart* newNode, TcpStreamSeqPart* nextNode);

			/// @brief Insert a range of nodes into the list after a given previous node.
			///
			/// See the overload that takes a previous node pointer for details.
			void insertNodeRangeAfter(NodeIndexList& list, TcpStreamSeqPart::PartId prevId, TcpStreamSeqPart* startNode,
			                          TcpStreamSeqPart* endNode);

			/// @brief Inserts a range of nodes into the list after a given previous node.
			///
			/// If the previous node is null, the new nodes are inserted at the head of the list.
			/// Otherwise they are inserted after the previous node.
			///
			/// The node range MUST fufill the following conditions:
			///  - The nodes in the range MUST be allocated on the m_Parts buffer.
			///  - The nodes in the range MUST be linked together as a chain, and not be linked to any other list.
			///  - The endNode must be reachable from the startNode by following the nextId links
			///  - The startNode must be reachable from the endNode by following the prevId links.
			///
			/// In practice this is used to insert a list of nodes into another list.
			///
			/// @param[in] list The list to insert the new nodes into.
			/// @param[in] prevNode The previous node to insert after, or null to insert at the head of the list.
			/// @param[in] startNode The first node in the range to insert.
			/// @param[in] endNode The last node in the range to insert.
			void insertNodeRangeAfter(NodeIndexList& list, TcpStreamSeqPart* prevNode, TcpStreamSeqPart* startNode,
			                          TcpStreamSeqPart* endNode);

			/// @brief Extracts a node from the list, unlinking it from its previous and next nodes.
			/// @param[in] list The list to extract the node from.
			/// @param[in] node The node to extract. Must be currently linked in the list.
			void extractNode(NodeIndexList& list, TcpStreamSeqPart* node);

			/// @brief Extracts a range of nodes from the list, unlinking them from their previous and next nodes.
			///
			/// The nodes are still kept linked together as a chain, but the chain is unlinked from the list and can be
			/// re-linked elsewhere.
			///
			/// @param[in] list The list to extract the nodes from.
			/// @param[in] startNode The first node in the range to extract. Must be currently linked in the list.
			/// @param[in] endNode The last node in the range to extract. Must be currently linked in the list, and must
			/// be after the startNode.
			void extractNodeRange(NodeIndexList& list, TcpStreamSeqPart* startNode, TcpStreamSeqPart* endNode);
#pragma endregion Intrusive Index List API

#pragma region Free List API
			/// @brief Take a part from the unused parts pool and bring it in-use.
			/// @return A pointer to the part.
			TcpStreamSeqPart* takeFreePart();

			/// @brief Take a range of parts from the unused parts pool and bring them in-use.
			/// @param[in] count The number of parts to get.
			/// @return A pair of startNode and endNode of the range.
			std::pair<TcpStreamSeqPart*, TcpStreamSeqPart*> takeFreePartRange(size_t count);

			/// @brief Return a part to the unused parts pool.
			/// @param part A pointer to the part.
			void returnFreePart(TcpStreamSeqPart* part)
			{
				// When parts are not in use, they are linked together with other free parts using the nextId
				// attribute. This makes the logical free list of parts, and allows us to reuse parts without
				// having to search for them or maintain a separate free list.
				insertNodeAfter(m_FreeSlotsList, nullptr, part);
			}

			/// @brief Return a range of parts to the unused parts pool.
			/// 
			/// The entire range MUST fuil the requirements of insertNodeRange.
			/// 
			/// @param startNode The first node in the range.
			/// @param endNode The last node in the range.
			void returnFreePartRange(TcpStreamSeqPart* startNode, TcpStreamSeqPart* endNode)
			{
				insertNodeRangeAfter(m_FreeSlotsList, nullptr, startNode, endNode);
			}
#pragma endregion

			/// @brief Represents the result of a Head-of-Line (HOL) unblock operation on a TCP stream sequence.
			struct HOLUnblockResult
			{
				/// @brief A pointer to the head part of the unblocked chain of sequence parts.
				TcpStreamSeqPart* head = nullptr;
				/// @brief A pointer to the tail part of the unblocked chain of sequence parts.
				TcpStreamSeqPart* tail = nullptr;
				/// @brief The PartId of the head part of the unblocked chain, if the head part is valid.
				uint32_t headId = TcpStreamSeqPart::INVALID_PART_ID;
			};

			/// @brief Attempts to unblock the head of line of the given list if the head part has the expected sequence
			/// number.
			///
			/// If the head of line is at the expected sequence number, the operation will extract and return
			/// a sublist of contigous parts starting from the head of line, which can now be considered in-order.
			///
			/// The next expected sequence number after the unblocked chain can be calculated using the returned tail
			/// part's nextSeqNum() function.
			///
			/// NOTE: The list is required to be ordered by sequence number, with the head being the part with the
			/// lowest sequence number.
			///
			/// @param[in] list The list to unblock the head of line from. This is typically the reorder buffer list.
			/// @param[in] expSeqNum The expected sequence number of the head part. If the head part does not have this
			/// sequence number, the unblock operation will fail.
			/// @return A HOLUnblockResult struct containing the result of the operation.
			HOLUnblockResult tryUnblockHeadOfLine(NodeIndexList& list, uint32_t expSeqNum);

			/// @brief Forces the unblock of the head of line of the given list to the given sequence number.
			///
			/// The function is similar to tryUnblockHeadOfLine, but it will unblock non-contiguous parts if necessary
			/// to unblock the line until the expected sequence number is reached. Afterwards, it will proceed the
			/// unblocking operation as tryUnblockHeadOfLine would, but with the new head of line after the forced
			/// unblock.
			///
			/// This function is intended to be used to consider all gaps prior to the expected sequence number as
			/// missing data, and unblock the line until the expected sequence number as if the missing data was
			/// received, even if it wasn't.
			///
			/// The resulting list of unblocked parts may contain gaps in the sequence numbers, which should be handled
			/// as missing data by the caller. The next expected sequence number after the unblocked chain can be
			/// calculated using the returned tail part's nextSeqNum() function.
			///
			/// NOTE: The list is required to be ordered by sequence number, with the head being the part with the
			/// lowest sequence number.
			///
			/// @param[in] list The list to unblock the head of line from. This is typically the reorder buffer list.
			/// @param[in] expSeqNum The expected sequence number to unblock to.
			/// @return A HOLUnblockResult struct containing the result of the operation.
			HOLUnblockResult forceUnblockHeadOfLineTo(NodeIndexList& list, uint32_t expSeqNum);

		private:
			std::vector<TcpStreamSeqPart> m_Parts;

			/// @brief The index of the first part in the out-of-order stream.
			///
			/// This is the part with the sequence number closest to the expected sequence number, and is the first part
			/// that should be checked for merging when a new part is inserted.
			NodeIndexList m_ReorderList;
			NodeIndexList m_FreeSlotsList;

			uint32_t m_ExpectedSeqNum = 0;
			/// @brief Close the stream when a fin flag is reached.
			bool m_StreamClosed = false;
		};
	}  // namespace internal

	class TcpByteStreamData
	{
	public:
		uint8_t const* m_Data;
		size_t dataLen = 0;
		size_t missingBytes = 0;
	};

	/// @brief This class represents a batch of TCP stream data segments.
	///
	/// When following a TCP connection, the reassembly engine reorders and deduplicates the received TCP segments into
	/// an ordered byte stream to be submitted to the user application.
	///
	class TcpStreamDataBatch
	{
	public:
		class Iterator
		{
		};

		Iterator begin() const;
		Iterator end() const;

		ConnectionData const& getConnection() const;

	private:
		ConnectionData m_Connection;
		internal::TcpByteStreamView m_StreamPartsView;
	};

	class TcpReassemblyV2
	{
		struct TcpConnection;

	public:
		enum class ConnectionEndReason
		{
			FinPacket,
			RstPacket,
			UserClosed,
		};

		class TcpDataReadyCtx
		{
		};

		class TcpConnectionStartCtx
		{
		};

		class TcpConnectionEndCtx
		{
		};

		/// @brief A callback invoked when new data arrives on a connection
		///
		/// @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where
		/// 0 is the first side seen in the connection and 1 is the second side seen
		/// @param[in] tcpData The TCP data itself + connection information
		/// @param[in] ctx A context object.
		using OnTcpDataReady =
		    std::function<void(int8_t side, const TcpStreamDataBatch& tcpData, TcpDataReadyCtx& ctx)>;

		/// @brief A callback invoked when a new TCP connection is identified.
		///
		/// The new connection may or may not begin with a SYN packet, depending on when the reassembly engine
		/// identifies the connection.
		///
		/// @param[in] metadata
		/// @param[in] ctx
		using OnTcpConnectionStart = std::function<void(const ConnectionData& metadata, TcpConnectionStartCtx& ctx)>;

		/// @brief A callback invoked when a TCP connection is terminated.
		///
		/// The connection may be terminated either by a FIN or RST packet, or manually by the user.
		///
		/// @param[in] metadata The connection info for the connection that is being terminated.
		/// @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user.
		/// @param[in] ctx
		using OnTcpConnectionEnd =
		    std::function<void(const ConnectionData& metadata, ConnectionEndReason reason, TcpConnectionEndCtx& ctx)>;

		/// @brief A unique identifier for a TCP flow, used for tracking and reassembly.
		using FlowKey = uint32_t;

		using ReassemblyStatus = TcpReassembly::ReassemblyStatus;

		/// @brief A connections proxy that provides an interface for accessing connection data information.
		class ConnectionsProxy;

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
			internal::TcpByteStream stream;
			uint16_t srcPort = 0;
			IPAddress srcIP;
		};

		struct TcpConnection
		{
			ConnectionData metadata;
			std::array<TcpConnectionSide, 2> side;
			int8_t openStreamSides = 0;
			int8_t lastReceivedSide = -1;
			bool closed = false;
		};

		using ConnectionMap = std::unordered_map<FlowKey, TcpConnection>;
		// using ConnectionInfoMap = std::unordered_map<FlowKey, ConnectionData>;

		Config m_Config;
		ConnectionMap m_Connections;

		OnTcpDataReady m_OnMessageReady;
		OnTcpConnectionStart m_OnConnectionStart;
		OnTcpConnectionEnd m_OnConnectionEnd;
	};

	/*
	class TcpReassemblyV2::ConnectionsProxy
	{
	    friend class TcpReassemblyV2;

	public:
	private:
	    ConnectionsProxy(TcpReassemblyV2::ConnectionMap const& data) noexcept : m_Data(&data)
	    {}

	    TcpReassemblyV2::ConnectionMap const* m_Data;
	};
	*/
}  // namespace pcpp