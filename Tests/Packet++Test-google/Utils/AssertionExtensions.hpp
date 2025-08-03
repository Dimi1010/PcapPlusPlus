#pragma once

#include <gtest\gtest.h>

namespace pcpp
{
	namespace test
	{
		/// @brief Compares two buffers for equality.
		/// @param actual Pointer to the actual buffer.
		/// @param actualLen Length of the actual buffer.
		/// @param expected Pointer to the expected buffer.
		/// @param expectedLen Length of the expected buffer.
		/// @return A gtest AssertionResult indicating whether the buffers match.
		::testing::AssertionResult BuffersMatch(const uint8_t* actual, size_t actualLen, const uint8_t* expected,
		                                        size_t expectedLen);

		/// @brief Compares two buffers for equality, assuming they have the same length.
		/// @param actual Pointer to the actual buffer.
		/// @param expected Pointer to the expected buffer.
		/// @param len Length of both buffers.
		/// @return A gtest AssertionResult indicating whether the buffers match.
		::testing::AssertionResult BuffersMatch(const uint8_t* actual, const uint8_t* expected, size_t len);
	}  // namespace test
}  // namespace pcpp