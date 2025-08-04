cmake_minimum_required(VERSION 3.14)


add_executable(
  Packet++Test-Google
  "main.cpp"
  "TestEnvironment.cpp"
  "Tests/PacketUtilsTests.cpp"
  "Tests/PacketTests.cpp"
  "Utils/AssertionExtensions.cpp"
  "Utils/PacketFactory.cpp"
)

target_compile_features(Packet++Test-Google PUBLIC cxx_std_14)
target_link_libraries(
  Packet++Test-Google
  PUBLIC memplumber Packet++ EndianPortable gtest gmock
)

target_include_directories(Packet++Test-Google PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_precompile_headers(Packet++Test-Google PRIVATE "pch.h")

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Packet++Test-Google PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
add_test(
  NAME Packet++Test-Google
  COMMAND $<TARGET_FILE:Packet++Test-Google>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
)
