#pragma once

#define NOMINMAX

#include <iostream>
#include <limits>
#include <list>
#include "TcpReassembly.h"
#include "AssertionUtils.h"
#include "PacketUtils.h"

#define PCPP_LOG_DEBUG(m) std::cerr << m << '\n';
#define PCPP_LOG_INFO(m) std::cerr << m << '\n';
#define PCPP_LOG_WARN(m) std::cerr << m << '\n';
#define PCPP_LOG_ERROR(m) std::cerr << m << '\n';

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
		/// @brief The relative distance between two sequence numbers, accounting for wraparound.
		/// @param seqNum1 The first sequence number.
		/// @param seqNum2 The second sequence number.
		/// @return The relative distance between the two sequence numbers.
		inline int32_t relativeDistanceSeqNum(uint32_t seqNum1, uint32_t seqNum2)
		{
			// TODO: Handle 0x80000000 distance case, which is ambiguous.
			return seqNum1 - seqNum2;
		}

		/// @brief Compares two sequence numbers using modular arithmetic to handle wraparound.
		/// @param seqNum1 The first sequence number to compare.
		/// @param seqNum2 The second sequence number to compare.
		/// @return A negative value if seqNum1 < seqNum2, zero if equal, or a positive value if seqNum1 > seqNum2.
		inline int32_t compareSeqNum(uint32_t seqNum1, uint32_t seqNum2)
		{
			// TODO: Handle 0x80000000 distance case, which is ambiguous.
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
		///
		/// The part uses 32-bit unsigned integer for buffer length and capacity, which means it can't represent buffers
		/// larger than 4GB. Since this is intended to represent a TCP stream part, this should be sufficient for most
		/// use cases.
		struct TcpStreamBufferedPart
		{
			using PartId = uint32_t;
			using HiResTimepoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

			static constexpr PartId INVALID_PART_ID = std::numeric_limits<PartId>::max();

			uint8_t* data = nullptr;  //< The pointer to the data buffer.
			uint32_t dataLen = 0;     //< The used capacity of the data buffer.
			uint32_t dataCap = 0;     //< The total capacity of the data buffer.
			uint32_t seqNum = 0;

			/// @brief The index of the next part in the chain. INVALID_PART_ID for no next part.
			/// @remarks Also used to indicate the next free part when the part is not in use.
			PartId nextId = INVALID_PART_ID;

			/// @brief The index of the prev part in the chain. INVALID_PART_ID for no prev part.
			PartId prevId = INVALID_PART_ID;

			/// @brief Additional flags related to the sequence part, such as SYN and FIN flags.
			SeqFlags seqFlags;

			bool ownsData = false;  //< Indicates whether this part is responsible for freeing the data buffer.

			~TcpStreamBufferedPart()
			{
				if (ownsData && data != nullptr)
				{
					delete[] data;
					data = nullptr;
				}
			}

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

		/// @brief A non-owning range view over a list of TcpStreamBufferedPart instances.
		///
		/// This class provides API for iterating over partial buffers of a TCP byte stream, which may be non-contiguous
		/// in memory due to out-of-order segment arrival.
		class TcpStreamBufferedPartsRange
		{
		public:
#pragma region Iterators
			class Iterator
			{
			public:
				using iterator_category = std::forward_iterator_tag;
				using value_type = TcpStreamBufferedPart const;
				using difference_type = std::ptrdiff_t;
				using pointer = TcpStreamBufferedPart const*;
				using reference = TcpStreamBufferedPart const&;

				Iterator() : m_View(nullptr), m_Current(nullptr)
				{}

				Iterator(TcpStreamBufferedPartsRange const* view, TcpStreamBufferedPart const* current)
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
				TcpStreamBufferedPartsRange const* m_View;
				TcpStreamBufferedPart const* m_Current;
			};
#pragma endregion Iterators

			TcpStreamBufferedPartsRange(TcpStreamBufferedPart::PartId firstId,
			                            std::vector<TcpStreamBufferedPart> const& buffer)
			    : TcpStreamBufferedPartsRange(firstId, ScalarBuffer<TcpStreamBufferedPart const>{
			          buffer.size() > 0 ? buffer.data() : nullptr, buffer.size() })
			{}

			TcpStreamBufferedPartsRange(TcpStreamBufferedPart::PartId firstId,
			                            ScalarBuffer<TcpStreamBufferedPart const> partsBuffer)
			    : m_PartsBuffer(std::move(partsBuffer)), m_FirstPartId(firstId)
			{}

			TcpStreamBufferedPart const* getFirstPart() const
			{
				if (m_FirstPartId == TcpStreamBufferedPart::INVALID_PART_ID)
				{
					return nullptr;
				}
				return m_PartsBuffer.buffer + m_FirstPartId;
			}

			TcpStreamBufferedPart const* getNextPart(TcpStreamBufferedPart const* part) const
			{
				if (part->nextId == TcpStreamBufferedPart::INVALID_PART_ID)
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

			/// @brief Calculates the number of missing bytes in the stream between two parts, if any.
			///
			/// The gap is determined by the difference between the next expected sequence number
			/// of the first part and the sequence number of the second part.
			///
			/// @param part The current part in the stream.
			/// @param nextPart The next part in the stream.
			/// @return The number of missing bytes.
			static size_t getGapBytes(TcpStreamBufferedPart const& part, TcpStreamBufferedPart const& nextPart)
			{
				auto rel = internal::relativeDistanceSeqNum(nextPart.seqNum, part.nextSeqNum());
				return rel > 0 ? rel : 0;
			}

		private:
			ScalarBuffer<TcpStreamBufferedPart const> m_PartsBuffer;
			TcpStreamBufferedPart::PartId m_FirstPartId = TcpStreamBufferedPart::INVALID_PART_ID;
		};

		/// @brief Event data provided to the user when new in-order data is ready in the TCP byte stream.
		struct TcpByteStreamDataReadyEvent
		{
			bool hasStackPart = false;
			int stackPart;

			/// @brief Additional parts that were dequeued
			///
			///
			TcpStreamBufferedPartsRange extraPartsRange;

			/// @brief The starting sequence number of the event.
			///
			/// This is the sequence number of the stream when the event was triggered.
			/// It isn't nessesarily the sequence number of the first part in the parts range,
			/// as there may be gaps in the parts range.
			uint32_t startSeqNum = 0;

			/// @brief The missing bytes in the stream before the first part in the parts range, if any.
			/// @return The number of missing bytes.
			size_t getLeadingMissingBytes() const
			{
				if (extraPartsRange.getFirstPart() == nullptr)
				{
					return 0;
				}

				// Negative relative distance shouldn't really happen.
				auto rel = internal::relativeDistanceSeqNum(extraPartsRange.getFirstPart()->seqNum, startSeqNum);
				return rel <= 0 ? 0 : rel;
			}
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
			/// The main method of the byte stream.
			///
			/// Used to insert TCP data segments into the stream and process them according to their sequence numbers.
			/// The method handles in-order segments, out-of-order segments, and retransmissions, ensuring that the user
			/// only receives a given data segment once and in the correct order.
			///
			/// @par In-order handling
			/// If an in-order segment is received, the stream will advance to the next expected seqNum and attempt
			/// to unblock any buffered out-of-order segments that can now be processed in order.
			///
			/// The provided callback 'onDataReady' will be invoked with all newly available in-order data segments,
			/// including the current segment and any previously buffered out-of-order segments that are now in order.
			///
			/// @par Out-of-order handling
			/// If a segment is received in out-of-order manner, it will be buffered internally until the missing
			/// data sequence is received.
			///
			/// @par Retransmission handling
			/// During retransmission a segment might be received that has a sequence number behind the head of line.
			/// Such segments will be ignored if they are fully behind the head of line. If they contain new data
			/// that extends after the head of line, the overlapping part is ignored and the new part is treated
			/// as in-order data segment.
			///
			/// @tparam OnDataReadyCallback A callback functor type that is invoked when new in-order data is ready.
			///
			/// The callback should have the signature `void(TcpByteStreamDataReadyEvent)`, where the parameter is the
			/// event data that contains the new in-order data segments.
			///
			/// @param[in] seqNum The sequence number of the segment.
			///
			/// Note that this includes the pre-sequence padding, meaning the true payload starts seqNum is "seqNum +
			/// seqNumExtra.preSeqNum".
			///
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
					                                          << flags.synFlag << ";FIN=" << flags.finFlag);

					// Temp part representing the new in-order part.
					TcpStreamBufferedPart tempPart;
					tempPart.data = data;
					tempPart.dataLen = dataLen;
					tempPart.seqNum = seqNum;
					tempPart.seqFlags = flags;

					// Fetch any buffered out-of-order parts that are now either past-head-of-line or in-order as a
					// result of the new head of line being at nextSeqNum.
					auto result = tryUnblockHeadOfLine(nextSeqNum);

					uint32_t nextExpectedSeqNum;
					if (result.head != nullptr)
					{
						// Handle edge case where the new part is in-order , but it overlaps with dequeued buffered
						// segments.
						//
						// Example:
						// HeadOfLine ->|<-
						// Next SEQ:    |                                ->|<-
						// New HOL:     |                                  |    ->|<-
						// Buffered:    |    [ 100 : 150 ),          [ 170 : 200 )|
						// Incoming:    |-----------[ 80 : 190 )-----------|      |
						//
						// In this case, we must remove all segments that are fully overlapped by the new segment,
						// and then trim the new segment to not overlap with any partially overlapped buffered segments.

						// If there are any buffered out-of-order parts that are now in-order, link them after the new
						// part. The linking is only forward link, due to inability to generate a valid PartID for the
						// temporary part representing the new in-order part.

						// Advance until we are past all parts that are fully inside the new segment.
						uint32_t currentId = result.headId;
						TcpStreamBufferedPart* current = result.head;
						while (current != nullptr && compareSeqNum(current->nextSeqNum(), nextSeqNum) < 0)
						{
							currentId = current->nextId;
							current = getPart(current->nextId);
						}

						// If current is nullptr, that means that all buffered parts are fully overlapped by the new
						// part, and can be ignored.
						if (current != nullptr)
						{
							// Clamp the new part to the start of the first non-fully overlapped part;
							tempPart.dataLen = current->seqNum - calcTrueSeqNum(seqNum, flags);

							// Link the new part to the first non-fully overlapped part, since it is now in-order.
							tempPart.nextId = currentId;
							nextExpectedSeqNum = result.tail->nextSeqNum();
						}
						else
						{
							nextExpectedSeqNum = nextSeqNum;
						}
					}
					else
					{
						nextExpectedSeqNum = nextSeqNum;
					}

					// Construct a view over the ordered parts and send it to the callback.
					// The current seqNum is sent to calculate the gap between the expected byte and the actual first
					// byte.
					TcpByteStreamDataReadyEvent event{ TcpStreamBufferedPartsRange(tempPart, m_Parts),
						                               m_ExpectedSeqNum };
					try
					{
						// Cast to const& to prevent sending non-const reference to the user.
						onDataReady(static_cast<TcpByteStreamDataReadyEvent const&>(event));
					}
					catch (std::exception const& ex)
					{
						// TODO: Log callback error
						PCPP_LOG_ERROR(ex.what());
					}

					// Check if FIN flag has been handled.

					// Release the unlinked parts back to the free list.
					if (result.head != nullptr)
					{
						returnFreePartRange(result.head, result.tail);
					}

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
					                                     << " bytes, but expected SEQ=" << m_ExpectedSeqNum
					                                     << ". SYN=" << flags.synFlag << ";FIN=" << flags.finFlag);
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
				auto result = tryUnblockHeadOfLine(seqNum);
				if (result.head == nullptr)
				{
					m_ExpectedSeqNum = seqNum;
					return;
				}

				// The current seqNum is sent to calculate the gap between the expected byte and the actual first byte.
				TcpByteStreamDataReadyEvent event{ TcpStreamBufferedPartsRange(*result.head, m_Parts),
					                               m_ExpectedSeqNum };
				try
				{
					// Cast to const& to prevent sending non-const reference to the user.
					onDataReady(static_cast<TcpByteStreamDataReadyEvent const&>(event));
				}
				catch (std::exception const& ex)
				{
					// TODO: Log callback error.
					PCPP_LOG_ERROR(ex.what());
				}

				uint32_t nextSeqNum = result.tail->nextSeqNum();
				returnFreePartRange(result.head, result.tail);

				m_ExpectedSeqNum = nextSeqNum;
			}

			/// @brief Reset the stream, clearing all buffered out-of-order parts and setting a new HOL sequence number.
			///
			/// This operation is typically called when the byte stream is to be reused for a new TCP connection.
			///
			/// No callbacks are invoked as a result of this operation, and all buffered data is discarded.
			/// If callbacks are desired, use setSeqHeadAndFlush instead.
			///
			/// @param[in] seqNum The initial sequence number that is expected on the new stream. Default is 0.
			void reset(uint32_t seqNum = 0);

			/// @brief Gets the status of the stream.
			///
			/// A stream is considered closed if a FIN or RST packet has been received.
			///
			/// @return True if the stream is open, false otherwise.
			bool isOpen() const
			{
				return m_StreamOpen;
			}

			uint32_t expectedSeq() const
			{
				return m_ExpectedSeqNum;
			}

			void reserveReorderBuffer(size_t numParts)
			{
				// Clamps the maximum buffer to the maximum number of parts that can be indexed by the PartId type.
				numParts = std::min(numParts, static_cast<size_t>(std::numeric_limits<PartId>::max()));
				m_Parts.reserve(numParts);
			}

		private:
			using PartId = TcpStreamBufferedPart::PartId;
#pragma region Buffered Parts Indexing
			/// @brief Get a pointer to a part by its id. Returns nullptr if the partId is invalid.
			/// @param[in] partId The id of the part to get.
			/// @return A pointer to the part with the given id, or nullptr if the partId is invalid.
			TcpStreamBufferedPart* getPart(PartId partId);

			/// @brief Get the id of a part from its pointer. Returns INVALID_PART_ID if the part pointer is null.
			///
			/// The pointer MUST BE a pointer to an element of the m_Parts vector or nullptr.
			///
			/// @param[in] part A pointer to the part.
			/// @return The id of the part, or INVALID_PART_ID if the part pointer is null.
			PartId getPartId(TcpStreamBufferedPart const* part) const;
#pragma endregion

#pragma region Intrusive Index List API
			struct NodeIndexList
			{
				PartId head = TcpStreamBufferedPart::INVALID_PART_ID;
			};

			/// @brief Insert a new node into the list after a given previous node.
			///
			/// See the overload that takes a previous node pointer for details.
			void insertNodeAfter(NodeIndexList& list, TcpStreamBufferedPart::PartId prevId,
			                     TcpStreamBufferedPart* newNode);

			/// @brief Insert a new node into the list after a given previous node.
			///
			/// If the previous node is null, the new node is inserted at the head of the list.
			/// Otherwise it is inserted after the previous node.
			///
			/// @param[in] list The list to insert the new node into.
			/// @param[in] prevNode The previous node to insert after, or null to insert at the head of the list.
			/// @param[in] newNode The new node to insert. Must not be linked in any list.
			void insertNodeAfter(NodeIndexList& list, TcpStreamBufferedPart* prevNode, TcpStreamBufferedPart* newNode);

			// void insertNodeBefore(NodeIndexList& list, TcpStreamBufferedPart* newNode, TcpStreamBufferedPart::PartId
			// nextId); void insertNodeBefore(NodeIndexList& list, TcpStreamBufferedPart* newNode,
			// TcpStreamBufferedPart* nextNode);

			/// @brief Insert a range of nodes into the list after a given previous node.
			///
			/// See the overload that takes a previous node pointer for details.
			void insertNodeRangeAfter(NodeIndexList& list, TcpStreamBufferedPart::PartId prevId,
			                          TcpStreamBufferedPart* startNode, TcpStreamBufferedPart* endNode);

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
			void insertNodeRangeAfter(NodeIndexList& list, TcpStreamBufferedPart* prevNode,
			                          TcpStreamBufferedPart* startNode, TcpStreamBufferedPart* endNode);

			/// @brief Extracts a node from the list, unlinking it from its previous and next nodes.
			/// @param[in] list The list to extract the node from.
			/// @param[in] node The node to extract. Must be currently linked in the list.
			void extractNode(NodeIndexList& list, TcpStreamBufferedPart* node);

			/// @brief Extracts a range of nodes from the list, unlinking them from their previous and next nodes.
			///
			/// The nodes are still kept linked together as a chain, but the chain is unlinked from the list and can be
			/// re-linked elsewhere.
			///
			/// @param[in] list The list to extract the nodes from.
			/// @param[in] startNode The first node in the range to extract. Must be currently linked in the list.
			/// @param[in] endNode The last node in the range to extract. Must be currently linked in the list, and must
			/// be after the startNode.
			void extractNodeRange(NodeIndexList& list, TcpStreamBufferedPart* startNode,
			                      TcpStreamBufferedPart* endNode);
#pragma endregion Intrusive Index List API

#pragma region Free List API
			/// @brief Take a part from the unused parts pool and bring it in-use.
			/// @return A pointer to the part.
			TcpStreamBufferedPart* takeFreePart();

			/// @brief Take a range of parts from the unused parts pool and bring them in-use.
			/// @param[in] count The number of parts to get.
			/// @return A pair of startNode and endNode of the range.
			std::pair<TcpStreamBufferedPart*, TcpStreamBufferedPart*> takeFreePartRange(size_t count);

			/// @brief Return a part to the unused parts pool.
			/// @param part A pointer to the part.
			void returnFreePart(TcpStreamBufferedPart* part)
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
			void returnFreePartRange(TcpStreamBufferedPart* startNode, TcpStreamBufferedPart* endNode)
			{
				insertNodeRangeAfter(m_FreeSlotsList, nullptr, startNode, endNode);
			}
#pragma endregion

#pragma region Reorder Buffer API
			/// @brief Represents the result of a Head-of-Line (HOL) unblock operation on a TCP stream sequence.
			struct HOLUnblockResult
			{
				/// @brief A pointer to the head part of the unblocked chain of sequence parts.
				TcpStreamBufferedPart* head = nullptr;
				/// @brief A pointer to the tail part of the unblocked chain of sequence parts.
				TcpStreamBufferedPart* tail = nullptr;
				/// @brief The PartId of the head part of the unblocked chain, if the head part is valid.
				uint32_t headId = TcpStreamBufferedPart::INVALID_PART_ID;
			};

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

			/// @brief Attempts to unblock the head of line of the reorder buffer.
			///
			/// The method will return a chain of all buffered parts that:
			/// - Have a sequence number that is less than or equal to the given expected sequence number.
			/// - Are contiguous in sequence numbers w.r.t the expected sequence number.
			///
			/// Parts that have sequence number less than the seqNum to unblock on may contain gaps in between.
			/// Those gaps are due to missing data that has not been buffered into the reorder buffer.
			///
			/// The next expected sequence number after the unblocked chain can be calculated using the returned tail
			/// part's nextSeqNum() function.
			///
			/// @warning No implicit HOL update
			/// This method does not update the m_ExpectedSeqNum. The caller should update the sequence number after the
			/// unblocked chain is handled.
			///
			/// @param[in] seqNum The expected sequence number to unblock on.
			/// @return A HOLUnblockResult struct containing the result of the operation.
			HOLUnblockResult tryUnblockHeadOfLine(uint32_t seqNum);

#pragma endregion Reorder Buffer API

		private:
			std::vector<TcpStreamBufferedPart> m_Parts;

			/// @brief The index of the first part in the out-of-order stream.
			///
			/// This is the part with the sequence number closest to the expected sequence number, and is the first part
			/// that should be checked for merging when a new part is inserted.
			NodeIndexList m_ReorderList;
			NodeIndexList m_FreeSlotsList;

			uint32_t m_ExpectedSeqNum = 0;
			/// @brief Stream is considered closed if a FIN flag has been received.
			bool m_StreamOpen = true;
		};
	}  // namespace internal

	class TcpStreamDataV2
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
	class TcpStreamDataV2Batch
	{
	public:
		class Iterator;

		Iterator begin() const;
		Iterator end() const;

		ConnectionData const& getConnection() const
		{
			return m_Connection;
		}

	private:
		ConnectionData m_Connection;
		internal::TcpByteStreamDataReadyEvent m_InternalEvent;
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

		/// @brief A callback function type invoked when TCP data is ready for processing.
		///
		/// This signature receives a single TCP stream data segment that is ready for processing.
		/// If multiple segments are unblocked at once, this callback will be invoked multiple times in order, once for
		/// each segment.
		///
		/// See OnTcpDataReadyBatch for a callback signature that receives a batch of segments at once.
		///
		/// @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where
		/// 0 is the first side seen in the connection and 1 is the second side seen.
		/// @param[in] tcpData The TCP data itself + connection information.
		/// @param[in] ctx A context object. Reserved for future use.
		using OnTcpDataReady = std::function<void(int8_t side, const TcpStreamDataV2& tcpData, TcpDataReadyCtx& ctx)>;

		/// @brief A callback function type invoked when TCP data is ready for processing.
		///
		/// This signature receives a batch of TCP stream data segments that are ready for processing, instead of a
		/// single segment. This should allow for more efficient procesing of segments, when multiple buffered segments
		/// are unblocked at once.
		///
		/// @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where
		/// 0 is the first side seen in the connection and 1 is the second side seen.
		/// @param[in] tcpData A batch of TCP data segments that are ready for processing + connection information.
		/// @param[in] ctx A context object. Reserved for future use.
		using OnTcpDataReadyBatch =
		    std::function<void(int8_t side, const TcpStreamDataV2Batch& tcpData, TcpDataReadyCtx& ctx)>;

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

		void setOnConnectionStartCallback(OnTcpConnectionStart callback);
		void setOnConnectionEndCallback(OnTcpConnectionEnd callback);

		void setOnDataReadyCallback(OnTcpDataReady callback);
		void setOnDataReadyCallback(OnTcpDataReadyBatch callback);

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
			std::array<TcpConnectionSide, 2> sides;
			int8_t openStreamSides = 0;
			int8_t lastReceivedSide = -1;
			bool closed = false;
		};

		using ConnectionMap = std::unordered_map<FlowKey, TcpConnection>;
		// using ConnectionInfoMap = std::unordered_map<FlowKey, ConnectionData>;

		// TODO: C++17 update - Replace with std::variant.
		class DataReadyCallback
		{
		public:
			enum class Type
			{
				Single,
				Batch
			};

			DataReadyCallback() : m_Type(Type::Single), m_SingleCallback()
			{}
			DataReadyCallback(OnTcpDataReady callback) : m_Type(Type::Single), m_SingleCallback(std::move(callback))
			{}
			DataReadyCallback(OnTcpDataReadyBatch callback) : m_Type(Type::Batch), m_BatchCallback(std::move(callback))
			{}

			~DataReadyCallback()
			{
				destroyActiveMem();
			}

			Type getType() const
			{
				return m_Type;
			}

			void setCallback(OnTcpDataReady callback)
			{
				swapToType(Type::Single);
				m_SingleCallback = std::move(callback);
			}
			void setCallback(OnTcpDataReadyBatch callback)
			{
				swapToType(Type::Batch);
				m_BatchCallback = std::move(callback);
			}

			OnTcpDataReady const* getSingleCallback() const
			{
				return m_Type == Type::Single ? &m_SingleCallback : nullptr;
			}
			OnTcpDataReadyBatch const* getBatchCallback() const
			{
				return m_Type == Type::Batch ? &m_BatchCallback : nullptr;
			}

		private:
			/// @brief Activates the given type in the union, destroying the active member if needed.
			void swapToType(Type newType) noexcept;

			/// @brief Manually call the destructor of the active member in the union.
			/// The caller should initialize a new union member immediately after this call.
			void destroyActiveMem() noexcept;

			Type m_Type = Type::Single;
			union {
				OnTcpDataReady m_SingleCallback;
				OnTcpDataReadyBatch m_BatchCallback;
			};
		};

		Config m_Config;
		ConnectionMap m_Connections;
		DataReadyCallback m_OnDataReady;
		OnTcpConnectionStart m_OnConnectionStart;
		OnTcpConnectionEnd m_OnConnectionEnd;
	};

	inline void testTcpReass()
	{
		TcpReassemblyV2 v2;
	}

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