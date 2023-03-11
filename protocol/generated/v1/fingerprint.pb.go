// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.22.2
// source: fingerprint.proto

//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LogicalFingerprint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Content []byte `protobuf:"bytes,1,opt,name=content" json:"content,omitempty"` // bytes identifier = 2;
}

func (x *LogicalFingerprint) Reset() {
	*x = LogicalFingerprint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fingerprint_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogicalFingerprint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogicalFingerprint) ProtoMessage() {}

func (x *LogicalFingerprint) ProtoReflect() protoreflect.Message {
	mi := &file_fingerprint_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogicalFingerprint.ProtoReflect.Descriptor instead.
func (*LogicalFingerprint) Descriptor() ([]byte, []int) {
	return file_fingerprint_proto_rawDescGZIP(), []int{0}
}

func (x *LogicalFingerprint) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

type CombinedFingerprints struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version           *uint32             `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	LocalFingerprint  *LogicalFingerprint `protobuf:"bytes,2,opt,name=local_fingerprint,json=localFingerprint" json:"local_fingerprint,omitempty"`
	RemoteFingerprint *LogicalFingerprint `protobuf:"bytes,3,opt,name=remote_fingerprint,json=remoteFingerprint" json:"remote_fingerprint,omitempty"`
}

func (x *CombinedFingerprints) Reset() {
	*x = CombinedFingerprints{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fingerprint_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CombinedFingerprints) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CombinedFingerprints) ProtoMessage() {}

func (x *CombinedFingerprints) ProtoReflect() protoreflect.Message {
	mi := &file_fingerprint_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CombinedFingerprints.ProtoReflect.Descriptor instead.
func (*CombinedFingerprints) Descriptor() ([]byte, []int) {
	return file_fingerprint_proto_rawDescGZIP(), []int{1}
}

func (x *CombinedFingerprints) GetVersion() uint32 {
	if x != nil && x.Version != nil {
		return *x.Version
	}
	return 0
}

func (x *CombinedFingerprints) GetLocalFingerprint() *LogicalFingerprint {
	if x != nil {
		return x.LocalFingerprint
	}
	return nil
}

func (x *CombinedFingerprints) GetRemoteFingerprint() *LogicalFingerprint {
	if x != nil {
		return x.RemoteFingerprint
	}
	return nil
}

var File_fingerprint_proto protoreflect.FileDescriptor

var file_fingerprint_proto_rawDesc = []byte{
	0x0a, 0x11, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x18, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x22, 0x2e, 0x0a,
	0x12, 0x4c, 0x6f, 0x67, 0x69, 0x63, 0x61, 0x6c, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72,
	0x69, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0xe8, 0x01,
	0x0a, 0x14, 0x43, 0x6f, 0x6d, 0x62, 0x69, 0x6e, 0x65, 0x64, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72,
	0x70, 0x72, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x59, 0x0a, 0x11, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72,
	0x70, 0x72, 0x69, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x66, 0x69, 0x6e, 0x67, 0x65,
	0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x63, 0x61, 0x6c, 0x46, 0x69,
	0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x52, 0x10, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
	0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x12, 0x5b, 0x0a, 0x12, 0x72,
	0x65, 0x6d, 0x6f, 0x74, 0x65, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e,
	0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69,
	0x6e, 0x74, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x63, 0x61, 0x6c, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72,
	0x70, 0x72, 0x69, 0x6e, 0x74, 0x52, 0x11, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x46, 0x69, 0x6e,
	0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x42, 0x05, 0x5a, 0x03, 0x2f, 0x76, 0x31,
}

var (
	file_fingerprint_proto_rawDescOnce sync.Once
	file_fingerprint_proto_rawDescData = file_fingerprint_proto_rawDesc
)

func file_fingerprint_proto_rawDescGZIP() []byte {
	file_fingerprint_proto_rawDescOnce.Do(func() {
		file_fingerprint_proto_rawDescData = protoimpl.X.CompressGZIP(file_fingerprint_proto_rawDescData)
	})
	return file_fingerprint_proto_rawDescData
}

var file_fingerprint_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_fingerprint_proto_goTypes = []interface{}{
	(*LogicalFingerprint)(nil),   // 0: signal.proto.fingerprint.LogicalFingerprint
	(*CombinedFingerprints)(nil), // 1: signal.proto.fingerprint.CombinedFingerprints
}
var file_fingerprint_proto_depIdxs = []int32{
	0, // 0: signal.proto.fingerprint.CombinedFingerprints.local_fingerprint:type_name -> signal.proto.fingerprint.LogicalFingerprint
	0, // 1: signal.proto.fingerprint.CombinedFingerprints.remote_fingerprint:type_name -> signal.proto.fingerprint.LogicalFingerprint
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_fingerprint_proto_init() }
func file_fingerprint_proto_init() {
	if File_fingerprint_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_fingerprint_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogicalFingerprint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fingerprint_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CombinedFingerprints); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_fingerprint_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_fingerprint_proto_goTypes,
		DependencyIndexes: file_fingerprint_proto_depIdxs,
		MessageInfos:      file_fingerprint_proto_msgTypes,
	}.Build()
	File_fingerprint_proto = out.File
	file_fingerprint_proto_rawDesc = nil
	file_fingerprint_proto_goTypes = nil
	file_fingerprint_proto_depIdxs = nil
}
