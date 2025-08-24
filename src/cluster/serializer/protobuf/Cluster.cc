// See the file "COPYING" in the main distribution directory for copyright.

#include "Cluster.h"

#include <string_view>

#include "zeek/Desc.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/Type.h"
#include "zeek/logging/Manager.h"
#include "zeek/logging/Types.h"
#include "zeek/threading/SerialTypes.h"
#include "zeek/util.h"

#include "Protobuf.h"
#include "event.pb.h"
#include "log.pb.h"

namespace zeek::cluster::protobuf {
using zeek::protobuf::deserialize;
using zeek::protobuf::serialize;

TypeTag to_tag(const zeek::protobuf::Type& type) {
    switch ( type ) {
        case zeek::protobuf::TYPE_BOOL: return TYPE_BOOL;
        case zeek::protobuf::TYPE_INT: return TYPE_INT;
        case zeek::protobuf::TYPE_COUNT: return TYPE_COUNT;
        case zeek::protobuf::TYPE_DOUBLE: return TYPE_DOUBLE;
        case zeek::protobuf::TYPE_TIME: return TYPE_TIME;
        case zeek::protobuf::TYPE_INTERVAL: return TYPE_INTERVAL;
        case zeek::protobuf::TYPE_STRING: return TYPE_STRING;
        case zeek::protobuf::TYPE_PATTERN: return TYPE_PATTERN;
        case zeek::protobuf::TYPE_ENUM: return TYPE_ENUM;
        case zeek::protobuf::TYPE_PORT: return TYPE_PORT;
        case zeek::protobuf::TYPE_ADDR: return TYPE_ADDR;
        case zeek::protobuf::TYPE_SUBNET: return TYPE_SUBNET;
        case zeek::protobuf::TYPE_ANY: return TYPE_ANY;
        case zeek::protobuf::TYPE_TABLE: return TYPE_TABLE;
        case zeek::protobuf::TYPE_RECORD: return TYPE_RECORD;
        case zeek::protobuf::TYPE_LIST: return TYPE_LIST;
        case zeek::protobuf::TYPE_FUNC: return TYPE_FUNC;
        case zeek::protobuf::TYPE_FILE: return TYPE_FILE;
        case zeek::protobuf::TYPE_VECTOR: return TYPE_VECTOR;
        case zeek::protobuf::TYPE_OPAQUE: return TYPE_OPAQUE;
        case zeek::protobuf::TYPE_TYPE: return TYPE_TYPE;
        case zeek::protobuf::TYPE_ERROR: return TYPE_ERROR;
        case zeek::protobuf::TYPE_VOID: [[fallthrough]];
        case zeek::protobuf::Type_INT_MIN_SENTINEL_DO_NOT_USE_: [[fallthrough]];
        case zeek::protobuf::Type_INT_MAX_SENTINEL_DO_NOT_USE_: return TYPE_VOID;
    }
}

bool ProtobufClusterEventSerializer::SerializeEvent(byte_buffer& buf, const Event& event) {
    zeek::protobuf::Event serialized;
    serialized.set_name(event.HandlerName());

    for ( const auto& arg : event.Args() )
        serialized.add_arg()->CopyFrom(serialize(*arg.get()));

    if ( event.Metadata() ) {
        for ( const auto& meta : *event.Metadata() )
            serialized.mutable_metadata()->insert({meta.Id(), serialize(*meta.Val())});
    }

    std::string data;

    if ( ! serialized.SerializeToString(&data) ) {
        reporter->Warning("unable to serialize event '%.*s'", static_cast<int>(event.HandlerName().size()),
                          event.HandlerName().data());
        return false;
    }

    std::ranges::transform(data, std::back_inserter(buf), [](char c) { return std::byte(c); });

    return true;
}

std::optional<Event> ProtobufClusterEventSerializer::UnserializeEvent(byte_buffer_span buf) {
    zeek::protobuf::Event deserialized;
    if ( ! deserialized.ParseFromArray(buf.data(), buf.size_bytes()) )
        return {};


    auto* handler = event_registry->Lookup(deserialized.name());
    if ( ! handler ) {
        reporter->Warning("skipping serialization of unknown event '%s'", deserialized.name().c_str());
        return {};
    }

    // Deserialize arguments.
    const auto& func = handler->GetFunc();
    if ( ! func ) {
        reporter->Warning("skipping serialization of event '%s' with unknown signature", deserialized.name().c_str());
        return {};
    }
    auto* fn = func.get();
    if ( ! fn ) {
        reporter->Warning("skipping serialization of event '%s' with unknown signature", deserialized.name().c_str());
        return {};
    }
    const auto& ty = fn->GetType();
    if ( ! ty ) {
        reporter->Warning("skipping serialization of event '%s' with unknown signature", deserialized.name().c_str());
        return {};
    }
    const auto& prototypes = ty->Prototypes();
    if ( prototypes.empty() ) {
        reporter->Warning("could not get prototype for event '%s'", deserialized.name().c_str());
        return {};
    }
    const auto& sig = prototypes[0];
    const auto& arguments = sig.args;
    if ( ! arguments ) {
        reporter->Warning("could not get prototype for event '%s'", deserialized.name().c_str());
        return {};
    }

    Args args;
    args.reserve(deserialized.arg_size());
    for ( auto i = 0; i < arguments->NumFields(); ++i ) {
        auto type_ = arguments->GetFieldType(i);
        if ( ! type_ ) {
            reporter->Warning("could not get argument type for field %d for event '%s'", i,
                              deserialized.name().c_str());
            return {};
        }

        args.push_back(deserialize(deserialized.arg(i), type_));
    }

    std::vector<detail::MetadataEntry> metadata_entries;
    metadata_entries.reserve(deserialized.metadata_size());
    for ( auto& [id, value] : deserialized.metadata() ) {
        // Skip unknown metadata entries.
        if ( auto* desc = event_registry->LookupMetadata(id) )
            metadata_entries.emplace_back(id, deserialize(value, desc->Type()));
    }

    return {{handler, args, std::make_unique<detail::EventMetadataVector>(std::move(metadata_entries))}};
}

bool ProtobufClusterLogSerializer::SerializeLogWrite(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                                     std::span<logging::detail::LogRecord> records) {
    zeek::protobuf::LogWriteBatch serialized;

    auto header_ = serialized.mutable_header();

    auto* stream_type = header.stream_id->GetType()->AsEnumType();
    auto* stream_name = stream_type->Lookup(header.stream_id->AsEnum());
    header_->set_stream(stream_name);

    auto* writer_type = header.writer_id->GetType()->AsEnumType();
    auto* writer_name = writer_type->Lookup(header.writer_id->AsEnum());
    header_->set_writer(writer_name);

    header_->set_filter(header.filter_name);
    header_->set_path(header.path);

    auto* fields = header_->mutable_fields();
    for ( const auto& f : header.fields ) {
        auto* field = fields->Add();

        field->set_name(f.name);
        field->set_secondary_name(f.secondary_name);
        field->set_type(zeek::protobuf::Type{static_cast<int>(f.type)});
        field->set_subtype(zeek::protobuf::Type{static_cast<int>(f.subtype)});
        field->set_is_optional(f.optional);
    }

    for ( auto& r : records ) {
        auto* record = serialized.mutable_records()->Add();

        for ( auto& v : r ) {
            bool have_error = false;
            auto* val = threading::Value::ValueToVal("protobuf log serializer", &v, have_error);

            // If we have any errors skip further processing.
            if ( have_error || ! val )
                return false;

            record->mutable_fields()->Add()->CopyFrom(protobuf::serialize(*val));
        }
    }

    std::string data;

    if ( ! serialized.SerializeToString(&data) )
        return false;

    std::ranges::transform(data, std::back_inserter(buf), [](char c) { return std::byte(c); });

    return true;
}

std::optional<logging::detail::LogWriteBatch> ProtobufClusterLogSerializer::UnserializeLogWrite(byte_buffer_span buf) {
    zeek::protobuf::LogWriteBatch proto;
    if ( ! proto.ParseFromArray(buf.data(), buf.size()) ) {
        reporter->Warning("unable to deserialize log record");
        return {};
    }

    static const auto& stream_id_type = zeek::id::find_type<zeek::EnumType>("Log::ID");
    static const auto& writer_id_type = zeek::id::find_type<zeek::EnumType>("Log::Writer");

    EnumValPtr stream_id;
    if ( auto id = stream_id_type->Lookup(proto.header().stream()) )
        stream_id = stream_id_type->GetEnumVal(id);

    EnumValPtr writer_id;
    if ( auto id = writer_id_type->Lookup(proto.header().writer()) )
        writer_id = writer_id_type->GetEnumVal(id);

    auto* columns = log_mgr->StreamColumns(stream_id.get());
    if ( ! columns ) {
        reporter->Warning("unable to get schema for log record '%s'", proto.header().stream().c_str());
        return {};
    }

    std::vector<threading::Field> fields; // The schema describing a log record.
    for ( const auto& f : proto.header().fields() ) {
        TypeTag type = to_tag(f.type());
        TypeTag subtype;
        fields.emplace_back(f.name().c_str(), f.secondary_name().c_str(), to_tag(f.type()), to_tag(f.subtype()),
                            f.is_optional());
    }

    logging::detail::LogWriteHeader header{stream_id, writer_id, proto.header().filter(), proto.header().path()};
    header.fields = std::move(fields);

    logging::detail::LogWriteBatch batch{.header = std::move(header)};

    batch.records.reserve(proto.records_size());
    for ( const auto& record : proto.records() ) {
        logging::detail::LogRecord data;
        data.reserve(record.fields_size());

        for ( auto i = 0; i < record.fields_size(); ++i ) {
            const auto& field = record.fields(i);
            const auto& column_type = columns->GetFieldType(i);

            bool have_error = false;
            auto val = protobuf::deserialize(field, column_type);

            // TODO(bbannier): Would be great to reuse `Manager::ValToLogVal` instead of copying it.
            if ( ! val ) {
                data.emplace_back(column_type->Tag(), false);
                continue;
            }

            threading::Value lval{column_type->Tag()};
            const auto& ty = column_type;

            switch ( ty->Tag() ) {
                case TYPE_BOOL: [[fallthrough]];
                case TYPE_INT: lval.val.int_val = val->AsInt(); break;

                case TYPE_ENUM: {
                    auto* s = ty->AsEnumType()->Lookup(val->AsInt());
                    if ( s ) {
                        auto s_ = std::string_view{s};
                        lval.val.string_val.data = util::copy_string(s_.data(), s_.size());
                        lval.val.string_val.length = s_.size();
                        break;
                    }
                    else {
                        auto err_msg = "enum type does not contain value:" + std::to_string(val->AsInt());
                        ty->Error(err_msg.c_str());
                        lval.val.string_val.data = util::copy_string("", 0);
                        lval.val.string_val.length = 0;
                    }
                    break;
                }

                case TYPE_COUNT: {
                    lval.val.uint_val = val->AsCount();
                    break;
                }

                case TYPE_PORT: {
                    auto p = val->AsCount();

                    auto pt = TRANSPORT_UNKNOWN;
                    auto pm = p & PORT_SPACE_MASK;
                    if ( pm == TCP_PORT_MASK )
                        pt = TRANSPORT_TCP;
                    else if ( pm == UDP_PORT_MASK )
                        pt = TRANSPORT_UDP;
                    else if ( pm == ICMP_PORT_MASK )
                        pt = TRANSPORT_ICMP;

                    lval.val.port_val.port = p & ~PORT_SPACE_MASK;
                    lval.val.port_val.proto = pt;
                    break;
                }

                case TYPE_SUBNET: {
                    val->AsSubNet().ConvertToThreadingValue(&lval.val.subnet_val);
                    break;
                }

                case TYPE_ADDR: {
                    val->AsAddr().ConvertToThreadingValue(&lval.val.addr_val);
                    break;
                }

                case TYPE_DOUBLE: [[fallthrough]];
                case TYPE_TIME: [[fallthrough]];
                case TYPE_INTERVAL: {
                    lval.val.double_val = val->AsDouble();
                    break;
                }

                case TYPE_STRING: {
                    auto s = val->AsString()->ToStdStringView();

                    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
                    lval.val.string_val.data = util::copy_string(s.data());
                    lval.val.string_val.length = s.size();
                    break;
                }

                // FIXME(bbannier): support these??
                case TYPE_FILE:
                case TYPE_FUNC:

                case TYPE_VOID:
                case TYPE_PATTERN:
                case TYPE_ANY:
                case TYPE_TABLE:
                case TYPE_RECORD:
                case TYPE_LIST:
                case TYPE_VECTOR:
                case TYPE_OPAQUE:
                case TYPE_TYPE:
                case TYPE_ERROR:
                    // FIXME(bbannier):
                    ODesc d;
                    ty->Describe(&d);
                    reporter->FatalError("deserialization unimplemented for '%s'", d.Description());
            }

            data.push_back(std::move(lval));
        }

        batch.records.push_back(std::move(data));
    }

    return {std::move(batch)};
}

} // namespace zeek::cluster::protobuf
