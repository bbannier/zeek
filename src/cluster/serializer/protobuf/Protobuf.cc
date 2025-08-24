// See the file "COPYING" in the main distribution directory for copyright.

#include "Protobuf.h"

#include <array>
#include <cassert>
#include <memory>

#include "zeek/Dict.h"
#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"

#include "zeek.pb.h"

namespace zeek::protobuf {

zeek::protobuf::Value serialize(const Val& val) {
    zeek::protobuf::Value value;

    switch ( val.GetType()->Tag() ) {
        case TYPE_BOOL: {
            value.mutable_scalar()->set_boolean(val.AsBool());
            break;
        }
        case TYPE_INT: {
            value.mutable_scalar()->set_int_(val.AsInt());
            break;
        }
        case TYPE_COUNT: value.mutable_scalar()->set_count(val.AsCount()); break;
        case TYPE_DOUBLE: {
            value.mutable_scalar()->set_real(val.AsDouble());
            break;
        }
        case TYPE_STRING: {
            value.mutable_scalar()->set_string(val.AsString()->ToStdStringView());
            break;
        }
        case TYPE_INTERVAL: {
            value.mutable_scalar()->mutable_timespan()->set_seconds(val.AsInterval());
            break;
        }
        case TYPE_TIME: {
            value.mutable_scalar()->mutable_timestamp()->set_seconds(val.AsTime());
            break;
        }
        case TYPE_PORT: {
            const auto* p = val.AsPortVal();

            auto* port = value.mutable_scalar()->mutable_port();
            port->set_value(p->Port());

            switch ( p->PortType() ) {
                case TRANSPORT_UNKNOWN: port->set_protocol(zeek::protobuf::PROTOCOL_UNKNOWN); break;
                case TRANSPORT_TCP: port->set_protocol(zeek::protobuf::Protocol::TCP); break;
                case TRANSPORT_UDP: port->set_protocol(zeek::protobuf::Protocol::UDP); break;
                case TRANSPORT_ICMP: port->set_protocol(zeek::protobuf::Protocol::ICMP); break;
            }

            break;
        }

        case TYPE_ENUM: {
            auto* enum_val = val.AsEnumVal();
            auto* enum_type = enum_val->GetType()->AsEnumType();
            auto name = enum_type->Lookup(enum_val->AsEnum());
            value.mutable_scalar()->set_enum_value(name);
            break;
        }

        case TYPE_ADDR: {
            const auto& addr = val.AsAddr();

            std::array<uint32_t, 4> n;
            addr.CopyIPv6(n.data());

            auto* address = value.mutable_scalar()->mutable_address();
            address->set_a1(n[0]);
            address->set_a2(n[1]);
            address->set_a3(n[2]);
            address->set_a4(n[3]);

            break;
        }

        case TYPE_SUBNET: {
            const auto& subnet = val.AsSubNet();

            auto* v = value.mutable_scalar()->mutable_subnet();

            std::array<uint32_t, 4> n;
            subnet.Prefix().CopyIPv6(n.data());

            v->mutable_prefix()->set_a1(n[0]);
            v->mutable_prefix()->set_a2(n[1]);
            v->mutable_prefix()->set_a3(n[2]);
            v->mutable_prefix()->set_a4(n[3]);

            v->set_length(subnet.Length());

            break;
        }

        case TYPE_RECORD: {
            auto* record_val = val.AsRecordVal();
            auto* record_type = record_val->GetType()->AsRecordType();

            for ( auto i = 0; i < record_val->NumFields(); ++i )
                value.mutable_record()->mutable_fields()->insert(
                    {record_type->FieldName(i), serialize(*record_val->GetField(i))});

            break;
        }

        case TYPE_VECTOR: {
            auto* vector_val = val.AsVectorVal();
            for ( auto i = 0; i < vector_val->Size(); ++i )
                value.mutable_vector()->add_values()->CopyFrom(serialize(*vector_val->ValAt(i)));
            break;
        }

        case TYPE_LIST: {
            auto* list_val = val.AsListVal();
            for ( auto i = 0; i < list_val->Length(); ++i )
                value.mutable_vector()->add_values()->CopyFrom(serialize(list_val[i]));
            break;
        }

        case TYPE_TABLE: {
            auto* table_val = val.AsTableVal();
            const auto& element_type = table_val->GetType()->Yield();

            auto is_set = val.GetType()->IsSet();

            auto table = table_val->AsTable();
            for ( const auto& te : *table ) {
                auto hash = te.GetHashKey();
                auto key = table_val->RecreateIndex(*hash);

                auto* entry = value.mutable_table()->add_values();

                zeek::protobuf::Vector keys;
                for ( auto i = 0; i < key->Length(); ++i )
                    entry->add_keys()->CopyFrom(serialize(*key->Idx(i).get()));

                if ( is_set )
                    entry->mutable_value()->mutable_scalar()->set_none(google::protobuf::NullValue{});
                else
                    entry->mutable_value()->CopyFrom(serialize(*te.value->GetVal().get()));
            }

            break;
        }

        case TYPE_VOID: {
            value.mutable_scalar()->set_none(::google::protobuf::NullValue{});
            break;
        }

        case TYPE_PATTERN: {
            value.mutable_scalar()->set_pattern(val.AsPattern()->PatternText());
            break;
        }

        // Unsupported types.
        case TYPE_ANY:
        case TYPE_FUNC:
        case TYPE_FILE:
        case TYPE_OPAQUE:
        case TYPE_TYPE:
        case TYPE_ERROR: {
            reporter->Warning("type not supported in protobuf serialization");
            break;
        }
    }

    return value;
}

ValPtr deserialize(const zeek::protobuf::Value& value, const TypePtr& type_) {
    switch ( value.kind_case() ) {
        case zeek::protobuf::Value::kScalar:
            switch ( value.scalar().kind_case() ) {
                case zeek::protobuf::Scalar::kBoolean: {
                    return val_mgr->Bool(value.scalar().boolean());
                }
                case zeek::protobuf::Scalar::kCount: {
                    return val_mgr->Count(value.scalar().count());
                }
                case zeek::protobuf::Scalar::kInt: {
                    return val_mgr->Int(value.scalar().int_());
                }
                case zeek::protobuf::Scalar::kPort: {
                    TransportProto proto = TRANSPORT_UNKNOWN;
                    switch ( value.scalar().port().protocol() ) {
                        case zeek::protobuf::TCP: {
                            proto = TRANSPORT_TCP;
                            break;
                        }
                        case zeek::protobuf::UDP: {
                            proto = TRANSPORT_UDP;
                            break;
                        }
                        case zeek::protobuf::ICMP: {
                            proto = TRANSPORT_ICMP;
                            break;
                        }
                        case zeek::protobuf::PROTOCOL_UNKNOWN: [[fallthrough]];
                        case zeek::protobuf::Protocol_INT_MIN_SENTINEL_DO_NOT_USE_: [[fallthrough]];
                        case zeek::protobuf::Protocol_INT_MAX_SENTINEL_DO_NOT_USE_: {
                            proto = TRANSPORT_UNKNOWN;
                            break;
                        }
                    }
                    return val_mgr->Port(value.scalar().port().value(), proto);
                }
                case zeek::protobuf::Scalar::kTimestamp: {
                    return make_intrusive<TimeVal>(value.scalar().timestamp().seconds());
                }
                case zeek::protobuf::Scalar::kTimespan: {
                    return make_intrusive<IntervalVal>(value.scalar().timespan().seconds());
                }
                case zeek::protobuf::Scalar::kString: {
                    return make_intrusive<StringVal>(value.scalar().string());
                }
                case zeek::protobuf::Scalar::kReal: {
                    return make_intrusive<DoubleVal>(value.scalar().real());
                }
                case zeek::protobuf::Scalar::kEnumValue: {
                    return id::find_val(value.scalar().enum_value());
                }

                case zeek::protobuf::Scalar::kAddress: {
                    std::array<uint32_t, 4> n{
                        value.scalar().address().a1(),
                        value.scalar().address().a2(),
                        value.scalar().address().a3(),
                        value.scalar().address().a4(),
                    };
                    auto addr = IPAddr{IPv6, n.data(), IPAddr::Network};
                    return make_intrusive<AddrVal>(std::move(addr));
                }

                case zeek::protobuf::Scalar::kSubnet: {
                    std::array<uint32_t, 4> n{
                        value.scalar().subnet().prefix().a1(),
                        value.scalar().subnet().prefix().a2(),
                        value.scalar().subnet().prefix().a3(),
                        value.scalar().subnet().prefix().a4(),
                    };
                    auto addr = IPAddr{IPv6, n.data(), IPAddr::Network};

                    auto width = value.scalar().subnet().length();

                    return make_intrusive<SubNetVal>(std::move(addr), static_cast<int>(width));
                }

                case zeek::protobuf::Scalar::kPattern: {
                    auto candidate = value.scalar().pattern();

                    // Remove any surrounding '/'s, not needed when creating an RE_matcher.
                    if ( candidate.size() > 2 && candidate.front() == candidate.back() && candidate.back() == '/' ) {
                        candidate.erase(0, 1);
                        candidate.erase(candidate.size() - 1);
                    }
                    // Remove any surrounding "^?(" and ")$?", automatically added below.
                    if ( candidate.size() > 6 && candidate.starts_with("^?(") && candidate.ends_with(")$?") ) {
                        candidate.erase(0, 3);
                        candidate.erase(candidate.size() - 3);
                    }

                    auto re = std::make_unique<RE_Matcher>(candidate.c_str());
                    if ( ! re->Compile() )
                        return {};

                    return make_intrusive<PatternVal>(re.release());
                }

                case zeek::protobuf::Scalar::kNone: [[fallthrough]];
                case zeek::protobuf::Scalar::KIND_NOT_SET: {
                    return {};
                }
            }

        case zeek::protobuf::Value::kRecord: {
            const auto& fields = value.record().fields();

            auto* record_type = type_->AsRecordType();
            auto val = make_intrusive<RecordVal>(IntrusivePtr{NewRef{}, record_type});

            for ( const auto& [name, value] : fields ) {
                auto idx = record_type->FieldOffset(name.c_str());

                // Skip unknown fields.
                if ( idx < 0 ) {
                    reporter->Warning("column '%s' unknown in '%s", name.c_str(), record_type->GetName().c_str());
                    continue;
                }

                val->Assign(idx, deserialize(value, record_type->GetFieldType(idx)));
            }

            return val;
        }

        case zeek::protobuf::Value::kVector: {
            const auto& values = value.vector().values();

            auto* type__ = type_->AsVectorType();
            assert(type__);

            auto vector_type = make_intrusive<VectorType>(type__->Yield());
            auto val = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, vector_type.get()});

            val->Reserve(values.size());
            for ( const auto& x : values )
                val->Append(deserialize(x, vector_type->Yield()));

            return val;
        }

        case zeek::protobuf::Value::kTable: {
            const auto& values = value.table().values();

            auto* table_type = type_->AsTableType();
            const auto& index_types = table_type->GetIndexTypes();

            auto table = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, table_type});

            for ( const auto& value : values ) {
                if ( index_types.size() < value.keys_size() ) {
                    reporter->Warning("received more index column than expected: %d vs %zu", value.keys_size(),
                                      index_types.size());
                    return {};
                }

                auto key_val = make_intrusive<ListVal>(TYPE_ANY);

                for ( auto i = 0; i < value.keys_size(); ++i )
                    key_val->Append(deserialize(value.keys(i), table_type->GetIndexTypes()[i]));

                table->Assign(key_val, deserialize(value.value(), table_type->Yield()));
            }

            return table;
        }

        case zeek::protobuf::Value::KIND_NOT_SET: break;
    }

    return {};
}

} // namespace zeek::protobuf
