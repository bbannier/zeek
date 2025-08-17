// See the file "COPYING" in the main distribution directory for copyright.

#include "Plugin.h"

#include <memory>

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/storage/Component.h"

#include "Cluster.h"
#include "Storage.h"

namespace zeek {
using namespace cluster;
using namespace plugin::protobuf_serializer;

plugin::Configuration Plugin::Configure() {
    AddComponent(new EventSerializerComponent("PROTOBUF", []() -> std::unique_ptr<EventSerializer> {
        return std::make_unique<cluster::protobuf::ProtobufClusterEventSerializer>();
    }));

    AddComponent(new LogSerializerComponent("PROTOBUF", []() -> std::unique_ptr<LogSerializer> {
        return std::make_unique<cluster::protobuf::ProtobufClusterLogSerializer>();
    }));

    AddComponent(new storage::SerializerComponent("PROTOBUF", []() -> std::unique_ptr<storage::Serializer> {
        return std::make_unique<storage::protobuf::ProtobufStorageSerializer>();
    }));

    plugin::Configuration config;
    config.name = "Zeek::Protobuf_Serialization_Format";
    config.description = "Serialization using Protocol Buffers";
    return config;
}
} // namespace zeek
