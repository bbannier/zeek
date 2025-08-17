FetchContent_Declare(
    protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG v32.0
    SOURCE_SUBDIR cmake FIND_PACKAGE_ARGS NAMES protobuf)
FetchContent_MakeAvailable(protobuf)

include(FindProtobuf)
find_package(protobuf CONFIG REQUIRED)

zeek_add_plugin(
    Zeek Protobuf_Serialization_Format
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES Plugin.cc Protobuf.cc Cluster.cc Storage.cc
    BIFS protobuf.bif)

target_link_libraries(plugin-Zeek-Protobuf_Serialization_Format PRIVATE protobuf::libprotobuf)

protobuf_generate(
    TARGET
    plugin-Zeek-Protobuf_Serialization_Format
    PROTOS
    zeek.proto
    event.proto
    log.proto
    LANGUAGE
    cpp)
