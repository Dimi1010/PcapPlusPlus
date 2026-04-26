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
			using HiResTimepoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

			HiResTimepoint timestamp;  //< The timestamp when this part was received.
			uint8_t* data = nullptr;   //< The pointer to the data buffer.
			uint32_t dataLen = 0;      //< The used capacity of the data buffer.
			uint32_t dataCap = 0;      //< The total capacity of the data buffer.
			uint32_t seqNum = 0;       //< The sequence number of the data buffer.

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

		/// @brief Event data provided to the user when new in-order data is ready in the TCP byte stream.
		struct TcpByteStreamDataReadyEvent
		{
			using HiResTimepoint = TcpStreamBufferedPart::HiResTimepoint;

			struct MainPart
			{
				HiResTimepoint timestamp;  //< The timestamp when the main part was received.
				uint8_t const* data;       //< The pointer to the main part of the data buffer that triggered the event.
				uint32_t dataLen;          //< The length of the main part of the data buffer
				uint32_t seqNum;           //< The sequence number of the main part of the data buffer.
				SeqFlags seqFlags;  //< The sequence flags associated with the main part, such as SYN and FIN flags.
			};

			/// @brief This is the part of incoming data that triggered the event. If any.
			MainPart mainPart;

			/// @brief Additional parts that were dequeued from the reorder buffer after the main part.
			std::list<TcpStreamBufferedPart> extraParts;

			/// @brief The starting sequence number of the event.
			///
			/// This is the sequence number of the stream when the event was triggered.
			/// It isn't nessesarily the sequence number of the first part in the parts range,
			/// as there may be gaps in the parts range.
			uint32_t startSeqNum = 0;

			/// @brief If this is true, the event contains a main part.
			/// Otherwise, the event only contains extra parts that were unblocked from the reorder buffer by another
			/// operation.
			bool hasMainPart = false;

			/// @brief The missing bytes in the stream before the first part in the parts range, if any.
			/// @return The number of missing bytes.
			size_t getLeadingMissingBytes() const
			{
				if (hasMainPart)
				{
					auto rel = internal::relativeDistanceSeqNum(mainPart.seqNum, startSeqNum);
					return rel <= 0 ? 0 : rel;
				}

				if (extraParts.empty())
				{
					return 0;
				}

				// Negative relative distance shouldn't really happen.
				auto rel = internal::relativeDistanceSeqNum(extraParts.front().seqNum, startSeqNum);
				return rel <= 0 ? 0 : rel;
			}

			uint32_t nextSeqPart() const
			{
				if (!extraParts.empty())
				{
					return extraParts.back().nextSeqNum();
				}

				if (hasMainPart)
				{
					return calcNextSeqNum(mainPart.seqNum, mainPart.dataLen, mainPart.seqFlags);
				}

				return startSeqNum;
			}
		};

		/// @brief A class that handles a singular unidirectional TCP byte stream reassembly.
		///
		/// The class provides an API for inserting newly received parts of the stream and a callback mechanism to
		/// notify the user when new in-order data is ready.
		class TcpByteStream
		{
			using PartBufferList = std::list<TcpStreamBufferedPart>;

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

					// Fetch any buffered out-of-order parts that are now either past-head-of-line or in-order as a
					// result of the new head of line being at nextSeqNum.
					auto result = tryUnblockHeadOfLine(nextSeqNum);
					auto& unblockedParts = result.unblockedParts;

					// Fully overlapped parts won't be sent to the user,
					// but need to be stored to be released to the free list.
					PartBufferList overlappedParts;

					uint32_t nextExpectedSeqNum;
					if (!unblockedParts.empty())
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
						auto currentIt = unblockedParts.begin();
						while (currentIt != unblockedParts.end() &&
						       compareSeqNum(currentIt->nextSeqNum(), nextSeqNum) < 0)
						{
							++currentIt;
						}

						// If current is nullptr, that means that all buffered parts are fully overlapped by the new
						// part, and can be ignored.
						if (currentIt != unblockedParts.end())
						{
							// Clamp the new part to the start of the first non-fully overlapped part;
							dataLen = currentIt->seqNum - calcTrueSeqNum(seqNum, flags);

							// Transfer all fully overlapped parts to the overlapped list to be released back to the
							// free list later.
							overlappedParts.splice(overlappedParts.begin(), unblockedParts, unblockedParts.begin(),
							                       currentIt);

							nextExpectedSeqNum = unblockedParts.back().nextSeqNum();
						}
						else
						{
							// All buffered parts are fully overlapped by the new part, so we can ignore them.
							overlappedParts.splice(overlappedParts.begin(), unblockedParts);
							nextExpectedSeqNum = nextSeqNum;
						}
					}
					else
					{
						nextExpectedSeqNum = nextSeqNum;
					}

					// Compose the event to be pushed.
					TcpByteStreamDataReadyEvent event;
					event.hasMainPart = true;
					event.mainPart.data = data;
					event.mainPart.dataLen = dataLen;
					event.mainPart.seqNum = seqNum;
					event.mainPart.seqFlags = flags;

					event.extraParts = std::move(unblockedParts);

					// The seq num of the stream when the event was triggered.
					event.startSeqNum = m_ExpectedSeqNum;

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
					returnFreeParts(overlappedParts);
					returnFreeParts(event.extraParts);

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
				if (result.unblockedParts.empty())
				{
					m_ExpectedSeqNum = seqNum;
					return;
				}

				TcpByteStreamDataReadyEvent event;
				event.hasMainPart = false;
				event.extraParts = std::move(result.unblockedParts);
				event.startSeqNum = m_ExpectedSeqNum;
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

				uint32_t nextSeqNum = event.extraParts.back().nextSeqNum();
				returnFreeParts(event.extraParts);
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

		private:
#pragma region Free List API

			/// @brief Takes up to count parts from the unused parts pool and returns them as a list.
			/// @param count The number of parts to take.
			/// @return A list of parts taken from the unused parts pool.
			PartBufferList takeFreeParts(size_t count);

			/// @brief Returns a list of parts to the unused parts pool.
			/// @param parts A lvalue reference to a list of parts to return. The list will be empty after the call.
			void returnFreeParts(PartBufferList& parts);
#pragma endregion

#pragma region Reorder Buffer API
			/// @brief Represents the result of a Head-of-Line (HOL) unblock operation on a TCP stream sequence.
			struct HOLUnblockResult
			{
				/// @brief A list of buffered parts that are now in-order.
				PartBufferList unblockedParts;
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
			/// @brief A list of buffered out-of-order parts, ordered by sequence number.
			PartBufferList m_ReorderBuffer;

			/// @brief A list of free parts that can be used for buffering new out-of-order segments.
			///
			/// This is used to avoid dynamic memory allocation for each new out-of-order segment,
			/// by reusing parts that have previously been used and are now free.
			PartBufferList m_FreeListCache;

			uint32_t m_ExpectedSeqNum = 0;
			/// @brief Stream is considered closed if a FIN flag has been received.
			bool m_StreamOpen = true;
		};
	}  // namespace internal

	class TcpStreamDataV2
	{
	public:
		using HiResTimepoint = internal::TcpStreamBufferedPart::HiResTimepoint;

		/// @brief A pointer to the TCP data buffer that is ready for processing.
		uint8_t const* m_Data;
		/// @brief The length of the data buffer.
		size_t dataLen = 0;
		/// @brief Leading missing bytes in the stream before this data segment, if any.
		size_t missingBytes = 0;

		/// @brief The timestamp when this data segment was received.
		///
		/// This field contains the timestamp of the packet containing this TCP data segment.
		///
		/// @par Timestamp preservation
		/// TODO: Add explanation on timestamp preservation.
		HiResTimepoint timestamp;
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

	private:
		internal::TcpByteStreamDataReadyEvent m_InternalEvent;
	};

	class TcpReassemblyV2
	{
		struct TcpConnection;

	public:
		struct Config
		{
			/// @brief Controls if the reassembly engine should preserve the original timestamps of each TCP segment.
			///
			///
			// bool preservePreciseTimestamps = true;
		};

		enum class ConnectionEndReason
		{
			FinPacket,
			RstPacket,
			UserClosed,
		};

		class TcpDataReadyCtx
		{
		public:
			// private:
			Config const& engineConfig;
		};

		class TcpConnectionStartCtx
		{
		public:
			// private:
			Config const& engineConfig;
		};

		class TcpConnectionEndCtx
		{
		public:
			// private:
			Config const& engineConfig;
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
		/// @param[in] conn The connection metadata for the connection this data belongs to.
		/// @param[in] ctx A context object. Reserved for future use.
		using OnTcpDataReady = std::function<void(int8_t side, const TcpStreamDataV2& tcpData,
		                                          const ConnectionData& conn, TcpDataReadyCtx& ctx)>;

		/// @brief A callback function type invoked when TCP data is ready for processing.
		///
		/// This signature receives a batch of TCP stream data segments that are ready for processing, instead of a
		/// single segment. This should allow for more efficient procesing of segments, when multiple buffered segments
		/// are unblocked at once.
		///
		/// @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where
		/// 0 is the first side seen in the connection and 1 is the second side seen.
		/// @param[in] tcpData A batch of TCP data segments that are ready for processing + connection information.
		/// @param[in] conn The connection metadata for the connection this data belongs to.
		/// @param[in] ctx A context object. Reserved for future use.
		using OnTcpDataReadyBatch = std::function<void(int8_t side, const TcpStreamDataV2Batch& tcpData,
		                                               const ConnectionData& conn, TcpDataReadyCtx& ctx)>;

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
		class ConnectionsProxyView;

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