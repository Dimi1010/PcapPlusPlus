cmake_minimum_required(VERSION 3.14)

if("cxx_std_14" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if(
    (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_SYSTEM_PROCESSOR)
    AND (NOT MINGW)
    AND (NOT CMAKE_OSX_ARCHITECTURES OR (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_OSX_ARCHITECTURES))
  )
    include(FetchContent)

    # Fetch Google Benchmark
    FetchContent_Declare(benchmark GIT_REPOSITORY https://github.com/google/benchmark.git GIT_TAG v1.9.0)

    # Disable testing and installation for Google Benchmark
    set(BENCHMARK_ENABLE_TESTING OFF)
    set(BENCHMARK_ENABLE_INSTALL OFF)
    FetchContent_MakeAvailable(benchmark)
  else()
    message(WARNING "Google Benchmark backend is not supported for cross-compilation")
  endif()
else()
  message(WARNING "Google Benchmark backend requires C++14 support")
endif()

add_executable(Playground main.cpp "TcpReassemblyNext.h" "TcpReassemblyNext.cpp")

target_link_libraries(Playground PUBLIC PcapPlusPlus::Pcap++ memplumber benchmark::benchmark EndianPortable)

target_compile_features(Playground PUBLIC cxx_std_20)
