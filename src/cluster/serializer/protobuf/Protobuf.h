// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Type.h"

#include "zeek.pb.h"

namespace zeek {

namespace protobuf {
ValPtr deserialize(const zeek::protobuf::Value& value, const TypePtr& type_);
zeek::protobuf::Value serialize(const Val& val);
} // namespace protobuf

} // namespace zeek
