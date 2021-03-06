/* Copyright © 2019 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: BSD-2-Clause */

// Code generated. DO NOT EDIT.

/*
 * Interface file for service: ByodServiceInstances
 * Used by client-side stubs.
 */

package locale_services

import (
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/model"
)

type ByodServiceInstancesClient interface {

    // Delete BYOD policy service instance
    //
    // @param tier1IdParam Tier-1 id (required)
    // @param localeServiceIdParam Locale service id (required)
    // @param serviceInstanceIdParam Service instance id (required)
    // @throws InvalidRequest  Bad Request, Precondition Failed
    // @throws Unauthorized  Forbidden
    // @throws ServiceUnavailable  Service Unavailable
    // @throws InternalServerError  Internal Server Error
    // @throws NotFound  Not Found
	Delete(tier1IdParam string, localeServiceIdParam string, serviceInstanceIdParam string) error

    // Read Tier1 BYOD service instance
    //
    // @param tier1IdParam Tier-1 id (required)
    // @param localeServiceIdParam Locale service id (required)
    // @param serviceInstanceIdParam Tier1 BYOD Service instance id (required)
    // @return com.vmware.nsx_policy.model.ByodPolicyServiceInstance
    // @throws InvalidRequest  Bad Request, Precondition Failed
    // @throws Unauthorized  Forbidden
    // @throws ServiceUnavailable  Service Unavailable
    // @throws InternalServerError  Internal Server Error
    // @throws NotFound  Not Found
	Get(tier1IdParam string, localeServiceIdParam string, serviceInstanceIdParam string) (model.ByodPolicyServiceInstance, error)

    // Read all Tier1 BYOD service instance objects under a tier-1
    //
    // @param tier1IdParam Tier-1 id (required)
    // @param localeServiceIdParam Locale service id (required)
    // @param cursorParam Opaque cursor to be used for getting next page of records (supplied by current result page) (optional)
    // @param includeMarkForDeleteObjectsParam Include objects that are marked for deletion in results (optional, default to false)
    // @param includedFieldsParam Comma separated list of fields that should be included in query result (optional)
    // @param pageSizeParam Maximum number of results to return in this page (server may return fewer) (optional, default to 1000)
    // @param sortAscendingParam (optional)
    // @param sortByParam Field by which records are sorted (optional)
    // @return com.vmware.nsx_policy.model.ByodPolicyServiceInstanceListResult
    // @throws InvalidRequest  Bad Request, Precondition Failed
    // @throws Unauthorized  Forbidden
    // @throws ServiceUnavailable  Service Unavailable
    // @throws InternalServerError  Internal Server Error
    // @throws NotFound  Not Found
	List(tier1IdParam string, localeServiceIdParam string, cursorParam *string, includeMarkForDeleteObjectsParam *bool, includedFieldsParam *string, pageSizeParam *int64, sortAscendingParam *bool, sortByParam *string) (model.ByodPolicyServiceInstanceListResult, error)

    // Create Tier1 BYOD Service Instance which represents instance of service definition created on manager.
    //
    // @param tier1IdParam Tier-1 id (required)
    // @param localeServiceIdParam Locale service id (required)
    // @param serviceInstanceIdParam Tier1 BYOD Service instance id (required)
    // @param byodPolicyServiceInstanceParam (required)
    // @throws InvalidRequest  Bad Request, Precondition Failed
    // @throws Unauthorized  Forbidden
    // @throws ServiceUnavailable  Service Unavailable
    // @throws InternalServerError  Internal Server Error
    // @throws NotFound  Not Found
	Patch(tier1IdParam string, localeServiceIdParam string, serviceInstanceIdParam string, byodPolicyServiceInstanceParam model.ByodPolicyServiceInstance) error

    // Create Tier1 BYOD Service Instance which represent instance of service definition created on manager.
    //
    // @param tier1IdParam Tier-1 id (required)
    // @param localeServiceIdParam Locale service id (required)
    // @param serviceInstanceIdParam Tier1 BYOD service instance id (required)
    // @param byodPolicyServiceInstanceParam (required)
    // @return com.vmware.nsx_policy.model.ByodPolicyServiceInstance
    // @throws InvalidRequest  Bad Request, Precondition Failed
    // @throws Unauthorized  Forbidden
    // @throws ServiceUnavailable  Service Unavailable
    // @throws InternalServerError  Internal Server Error
    // @throws NotFound  Not Found
	Update(tier1IdParam string, localeServiceIdParam string, serviceInstanceIdParam string, byodPolicyServiceInstanceParam model.ByodPolicyServiceInstance) (model.ByodPolicyServiceInstance, error)
}
