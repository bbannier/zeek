// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zeek/cluster/Event.h>
#include <zeek/cluster/Serializer.h>

namespace zeek::cluster::protobuf {
class ProtobufClusterEventSerializer : public EventSerializer {
public:
    ProtobufClusterEventSerializer() : EventSerializer("proto") {}

    bool SerializeEvent(byte_buffer& buf, const Event& event) override;

    std::optional<Event> UnserializeEvent(byte_buffer_span buf) override;
};

class ProtobufClusterLogSerializer : public LogSerializer {
public:
    ProtobufClusterLogSerializer() : LogSerializer("proto") {}

    bool SerializeLogWrite(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                           std::span<logging::detail::LogRecord> records) override;

    std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(byte_buffer_span buf) override;
};
} // namespace zeek::cluster::protobuf
