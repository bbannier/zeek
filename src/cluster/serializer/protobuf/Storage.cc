// See the file "COPYING" in the main distribution directory for copyright.

#include "Storage.h"

#include <optional>

#include "zeek/util-types.h"

#include "Protobuf.h"

namespace zeek::storage::protobuf {

using zeek::protobuf::deserialize;
using zeek::protobuf::serialize;

std::optional<byte_buffer> ProtobufStorageSerializer::Serialize(ValPtr val) {
    auto serialized = serialize(*val.get()).SerializeAsString();

    auto data = byte_buffer();
    data.reserve(serialized.size());
    for ( auto c : serialized )
        data.push_back(std::byte(c));

    return data;
}

expected<ValPtr, std::string> ProtobufStorageSerializer::Unserialize(byte_buffer_span buf, TypePtr type) {
    zeek::protobuf::Value proto;
    if ( ! proto.ParseFromArray(buf.data(), buf.size()) )
        return unexpected("failed to parse binary data as protobuf");

    return deserialize(proto, type);
}

} // namespace zeek::storage::protobuf
