#include "AssertionExtensions.hpp"

#include <iomanip>

namespace pcpp
{
	namespace test
	{
		namespace
		{
			::testing::Message createBufferRepr(const uint8_t* buffer, size_t size)
			{
				::testing::Message msg;
				if (buffer == nullptr || size == 0)
				{
					msg << "Buffer is null or empty";
					return msg;
				}

				for (size_t i = 0; i < size; ++i)
				{
					msg << std::setfill('0') << std::setw(2) << std::right << std::hex << static_cast<int>(buffer[i])
					    << " ";
				}

				msg << std::setfill(' ') << std::setw(0) << std::left << std::dec;
				return msg;
			}
		}  // namespace

		::testing::AssertionResult BuffersMatch(const uint8_t* actual, size_t actualLen, const uint8_t* expected,
		                                        size_t expectedLen)
		{
			auto const addActualBufferRepr = [actual, actualLen](::testing::AssertionResult& result) {
				result << "Actual buffer:   " << createBufferRepr(actual, actualLen) << '\n';
			};
			auto const addExpectedBufferRepr = [expected, expectedLen](::testing::AssertionResult& result) {
				result << "Expected buffer: " << createBufferRepr(expected, expectedLen) << '\n';
			};

			if (actual == nullptr && actualLen > 0)
			{
				return ::testing::AssertionFailure() << "Actual buffer is null but expected length is " << actualLen;
			}

			if (expected == nullptr && expectedLen > 0)
			{
				return ::testing::AssertionFailure() << "Expected buffer is null but actual length is " << expectedLen;
			}

			if (actual == nullptr && expected == nullptr)
			{
				return ::testing::AssertionSuccess() << "Both buffers are null";
			}

			if (actual == nullptr || expected == nullptr)
			{
				auto failure = ::testing::AssertionFailure() << "One of the buffers is null";
				addActualBufferRepr(failure);
				addExpectedBufferRepr(failure);
				return failure;
			}

			if (actualLen != expectedLen)
			{
				auto failure = ::testing::AssertionFailure();
				failure << (::testing::Message()
				            << "Buffers have different lengths: actual=" << actualLen << ", expected=" << expectedLen)
				        << '\n';

				addActualBufferRepr(failure);
				addExpectedBufferRepr(failure);
				return failure;
			}

			for (size_t i = 0; i < actualLen; ++i)
			{
				if (actual[i] != expected[i])
				{
					auto failure = ::testing::AssertionFailure();

					failure << "Buffers differ at index " << i << ": actual=" << static_cast<int>(actual[i])
					        << ", expected=" << static_cast<int>(expected[i]) << '\n';

					addActualBufferRepr(failure);
					addExpectedBufferRepr(failure);

					return failure;
				}
			}

			return ::testing::AssertionSuccess();
		}

		::testing::AssertionResult BuffersMatch(const uint8_t* actual, const uint8_t* expected, size_t len)
		{
			return BuffersMatch(actual, len, expected, len);
		}
	}  // namespace test
}  // namespace pcpp
