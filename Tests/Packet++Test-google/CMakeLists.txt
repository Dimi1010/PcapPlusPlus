cmake_minimum_required(VERSION 3.14)

include(FetchContent)

# TODO: This may have issues with brew as it doesn't allow the use of FetchContent.
FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.16.0)

if(WIN32)
  # Prevent overriding the parent project's compiler/linker settings.
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

FetchContent_MakeAvailable(googletest)

add_executable(
  Packet++Test-Google
  "main.cpp"
  "TestEnvironment.cpp"
  "Tests/PacketUtilsTests.cpp"
)

target_compile_features(Packet++Test-Google PUBLIC cxx_std_14)
target_link_libraries(Packet++Test-Google PUBLIC memplumber Packet++ EndianPortable gtest gmock)

target_include_directories(Packet++Test-Google PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_precompile_headers(Packet++Test-Google PRIVATE "pch.h")

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Packet++Test-Google PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test-Google PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
add_test(NAME Packet++Test-Google COMMAND $<TARGET_FILE:Packet++Test-Google> WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
