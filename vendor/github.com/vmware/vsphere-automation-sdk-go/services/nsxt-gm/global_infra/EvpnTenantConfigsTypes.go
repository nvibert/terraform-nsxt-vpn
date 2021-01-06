/* Copyright © 2019 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: BSD-2-Clause */

// Code generated. DO NOT EDIT.

/*
 * Data type definitions file for service: EvpnTenantConfigs.
 * Includes binding types of a structures and enumerations defined in the service.
 * Shared by client-side stubs and server-side skeletons to ensure type
 * compatibility.
 */

package global_infra

import (
	"reflect"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt-gm/model"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/bindings"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/data"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/protocol"
)





func evpnTenantConfigsPatchInputType() bindings.StructType {
	fields := make(map[string]bindings.BindingType)
	fieldNameMap := make(map[string]string)
	fields["config_id"] = bindings.NewStringType()
	fields["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	fieldNameMap["config_id"] = "ConfigId"
	fieldNameMap["evpn_tenant_config"] = "EvpnTenantConfig"
	var validators = []bindings.Validator{}
	return bindings.NewStructType("operation-input", fields, reflect.TypeOf(data.StructValue{}), fieldNameMap, validators)
}

func evpnTenantConfigsPatchOutputType() bindings.BindingType {
	return bindings.NewVoidType()
}

func evpnTenantConfigsPatchRestMetadata() protocol.OperationRestMetadata {
	fields := map[string]bindings.BindingType{}
	fieldNameMap := map[string]string{}
	paramsTypeMap := map[string]bindings.BindingType{}
	pathParams := map[string]string{}
	queryParams := map[string]string{}
	headerParams := map[string]string{}
	dispatchHeaderParams := map[string]string{}
	bodyFieldsMap := map[string]string{}
	fields["config_id"] = bindings.NewStringType()
	fields["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	fieldNameMap["config_id"] = "ConfigId"
	fieldNameMap["evpn_tenant_config"] = "EvpnTenantConfig"
	paramsTypeMap["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	paramsTypeMap["config_id"] = bindings.NewStringType()
	paramsTypeMap["configId"] = bindings.NewStringType()
	pathParams["config_id"] = "configId"
	resultHeaders := map[string]string{}
	errorHeaders := map[string]map[string]string{}
	return protocol.NewOperationRestMetadata(
		fields,
		fieldNameMap,
		paramsTypeMap,
		pathParams,
		queryParams,
		headerParams,
		dispatchHeaderParams,
		bodyFieldsMap,
		"",
		"evpn_tenant_config",
		"PATCH",
		"/global-manager/api/v1/global-infra/evpn-tenant-configs/{configId}",
		"",
		resultHeaders,
		204,
		"",
		errorHeaders,
		map[string]int{"com.vmware.vapi.std.errors.invalid_request": 400,"com.vmware.vapi.std.errors.unauthorized": 403,"com.vmware.vapi.std.errors.service_unavailable": 503,"com.vmware.vapi.std.errors.internal_server_error": 500,"com.vmware.vapi.std.errors.not_found": 404})
}

func evpnTenantConfigsUpdateInputType() bindings.StructType {
	fields := make(map[string]bindings.BindingType)
	fieldNameMap := make(map[string]string)
	fields["config_id"] = bindings.NewStringType()
	fields["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	fieldNameMap["config_id"] = "ConfigId"
	fieldNameMap["evpn_tenant_config"] = "EvpnTenantConfig"
	var validators = []bindings.Validator{}
	return bindings.NewStructType("operation-input", fields, reflect.TypeOf(data.StructValue{}), fieldNameMap, validators)
}

func evpnTenantConfigsUpdateOutputType() bindings.BindingType {
	return bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
}

func evpnTenantConfigsUpdateRestMetadata() protocol.OperationRestMetadata {
	fields := map[string]bindings.BindingType{}
	fieldNameMap := map[string]string{}
	paramsTypeMap := map[string]bindings.BindingType{}
	pathParams := map[string]string{}
	queryParams := map[string]string{}
	headerParams := map[string]string{}
	dispatchHeaderParams := map[string]string{}
	bodyFieldsMap := map[string]string{}
	fields["config_id"] = bindings.NewStringType()
	fields["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	fieldNameMap["config_id"] = "ConfigId"
	fieldNameMap["evpn_tenant_config"] = "EvpnTenantConfig"
	paramsTypeMap["evpn_tenant_config"] = bindings.NewReferenceType(model.EvpnTenantConfigBindingType)
	paramsTypeMap["config_id"] = bindings.NewStringType()
	paramsTypeMap["configId"] = bindings.NewStringType()
	pathParams["config_id"] = "configId"
	resultHeaders := map[string]string{}
	errorHeaders := map[string]map[string]string{}
	return protocol.NewOperationRestMetadata(
		fields,
		fieldNameMap,
		paramsTypeMap,
		pathParams,
		queryParams,
		headerParams,
		dispatchHeaderParams,
		bodyFieldsMap,
		"",
		"evpn_tenant_config",
		"PUT",
		"/global-manager/api/v1/global-infra/evpn-tenant-configs/{configId}",
		"",
		resultHeaders,
		200,
		"",
		errorHeaders,
		map[string]int{"com.vmware.vapi.std.errors.invalid_request": 400,"com.vmware.vapi.std.errors.unauthorized": 403,"com.vmware.vapi.std.errors.service_unavailable": 503,"com.vmware.vapi.std.errors.internal_server_error": 500,"com.vmware.vapi.std.errors.not_found": 404})
}


