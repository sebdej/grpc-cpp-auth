#  Copyright 2021 Sébastian Dejonghe
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.16)

project(grpc++ VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)

find_package(spdlog CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${PROTOBUF_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate_cpp(PROTO_SRC PROTO_HDR proto/hello_world.proto)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/hello_world.grpc.pb.cc" "${CMAKE_CURRENT_BINARY_DIR}/hello_world.grpc.pb.h"
  COMMAND protobuf::protoc -I=${CMAKE_CURRENT_SOURCE_DIR}/proto --grpc_out=${CMAKE_CURRENT_BINARY_DIR} --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin> hello_world.proto
  DEPENDS protobuf::protoc proto/hello_world.proto
  COMMENT "Running protoc for gRPC C++"
  VERBATIM)

add_executable(grpc-server src/main.cpp
	src/utilities.h src/utilities.cpp
	src/server_reactor.h src/server_reactor.cpp
	src/hello_world_service.h src/hello_world_service.cpp
	${PROTO_HDR} ${PROTO_SRC} "${CMAKE_CURRENT_BINARY_DIR}/hello_world.grpc.pb.cc" "${CMAKE_CURRENT_BINARY_DIR}/hello_world.grpc.pb.h")

target_link_libraries(grpc-server PRIVATE spdlog::spdlog_header_only)
target_link_libraries(grpc-server PRIVATE gRPC::gpr gRPC::upb gRPC::grpc gRPC::grpc++)
target_link_libraries(grpc-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)