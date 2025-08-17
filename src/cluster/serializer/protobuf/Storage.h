// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zeek/storage/Serializer.h>

namespace zeek::storage::protobuf {

class ProtobufStorageSerializer : public Serializer {
public:
    ProtobufStorageSerializer() : Serializer("proto") {}

    std::optional<byte_buffer> Serialize(ValPtr val) override;
    expected<ValPtr, std::string> Unserialize(byte_buffer_span buf, TypePtr type) override;
};

} // namespace zeek::storage::protobuf
