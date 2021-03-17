/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: MPL-2.0 */

package nsxt

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/protocol/client"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/infra"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/model"
)

var IPSecVpnSession_RESOURCE_TYPE = []string{

	model.IPSecVpnSession_RESOURCE_TYPE_POLICYBASEDIPSECVPNSESSION,
	model.IPSecVpnSession_RESOURCE_TYPE_ROUTEBASEDIPSECVPNSESSION,
	model.IPSecVpnSession_ENCRYPTION_ALGORITHMS_AES_GCM_256,
	model.IPSecVpnSession_ENCRYPTION_ALGORITHMS_NO_ENCRYPTION_AUTH_AES_GMAC_128,
	model.IPSecVpnSession_ENCRYPTION_ALGORITHMS_NO_ENCRYPTION_AUTH_AES_GMAC_192,
	model.IPSecVpnSession_ENCRYPTION_ALGORITHMS_NO_ENCRYPTION_AUTH_AES_GMAC_256,
	model.IPSecVpnSession_ENCRYPTION_ALGORITHMS_NO_ENCRYPTION,
}

var IPSecVpnSession_DIGEST_ALGORITHMS = []string{
	model.IPSecVpnSession_DIGEST_ALGORITHMS_SHA1,
	model.IPSecVpnSession_DIGEST_ALGORITHMS_SHA2_256,
	model.IPSecVpnSession_DIGEST_ALGORITHMS_SHA2_384,
	model.IPSecVpnSession_DIGEST_ALGORITHMS_SHA2_512,
}

var IPSecVpnSession_DH_GROUPS = []string{
	model.IPSecVpnSession_DH_GROUPS_GROUP14,
	model.IPSecVpnSession_DH_GROUPS_GROUP2,
	model.IPSecVpnSession_DH_GROUPS_GROUP5,
	model.IPSecVpnSession_DH_GROUPS_GROUP15,
	model.IPSecVpnSession_DH_GROUPS_GROUP16,
	model.IPSecVpnSession_DH_GROUPS_GROUP19,
	model.IPSecVpnSession_DH_GROUPS_GROUP20,
	model.IPSecVpnSession_DH_GROUPS_GROUP21,
}

func resourceNsxtPolicyIpsecVpnTunnelProfile() *schema.Resource {
	return &schema.Resource{
		Create: resourceNsxtPolicyIpsecVpnTunnelProfileCreate,
		Read:   resourceNsxtPolicyIpsecVpnTunnelProfileRead,
		Update: resourceNsxtPolicyIpsecVpnTunnelProfileUpdate,
		Delete: resourceNsxtPolicyIpsecVpnTunnelProfileDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"nsx_id":       getNsxIDSchema(),
			"path":         getPathSchema(),
			"display_name": getDisplayNameSchema(),
			"description":  getDescriptionSchema(),
			"revision":     getRevisionSchema(),
			"tag":          getTagsSchema(),
			"vpn_type": {
				Type:        schema.TypeString,
				Description: " A Policy Based VPN requires to define protect rules that match local and peer subnets. IPSec security associations is negotiated for each pair of local and peer subnet. A Route Based VPN is more flexible, more powerful and recommended over policy based VPN. IP Tunnel port is created and all traffic routed via tunnel port is protected. Routes can be configured statically or can be learned through BGP. A route based VPN is must for establishing redundant VPN session to remote site.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(IPSecVpnSession_RESOURCE_TYPE, false),
				},
				Required: false,
			},
			"digest_algorithms": {
				Type:        schema.TypeSet,
				Description: "Algorithm to be used for message digest during Internet Key Exchange(IKE) negotiation. Default is SHA2_256.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(IPSecVpnTunnelProfile_DIGEST_ALGORITHMS, false),
				},
				Required: true,
			},
			"dh_groups": {
				Type:        schema.TypeSet,
				Description: "Diffie-Hellman group to be used if PFS is enabled. Default is GROUP14.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(IPSecVpnTunnelProfile_DH_GROUPS, false),
				},
				Required: true,
			},
		},
	}
}

func resourceNsxtPolicyIpsecVpnTunnelProfileExists(id string, connector *client.RestConnector, isGlobalManager bool) (bool, error) {
	var err error

	client := infra.NewDefaultIpsecVpnTunnelProfilesClient(connector)
	_, err = client.Get(id)

	if err == nil {
		return true, nil
	}

	if isNotFoundError(err) {
		return false, nil
	}

	return false, logAPIError("Error retrieving resource", err)
}

func resourceNsxtPolicyIpsecVpnTunnelProfileCreate(d *schema.ResourceData, m interface{}) error {

	connector := getPolicyConnector(m)

	// Initialize resource Id and verify this ID is not yet used
	id, err := getOrGenerateID(d, m, resourceNsxtPolicyIpsecVpnTunnelProfileExists)
	if err != nil {
		return err
	}

	displayName := d.Get("display_name").(string)
	description := d.Get("description").(string)

	DhGroups := getStringListFromSchemaSet(d, "dh_groups")
	DigestAlgorithms := getStringListFromSchemaSet(d, "digest_algorithms")
	EncryptionAlgorithms := getStringListFromSchemaSet(d, "encryption_algorithms")

	obj := model.IPSecVpnTunnelProfile{
		DisplayName:          &displayName,
		Description:          &description,
		DhGroups:             DhGroups,
		DigestAlgorithms:     DigestAlgorithms,
		EncryptionAlgorithms: EncryptionAlgorithms,
	}

	// Create the resource using PATCH
	log.Printf("[INFO] Creating IpsecVpnTunnelProfile with ID %s", id)

	client := infra.NewDefaultIpsecVpnTunnelProfilesClient(connector)
	err = client.Patch(id, obj)

	if err != nil {
		return handleCreateError("IpsecVpnTunnelProfile", id, err)
	}

	d.SetId(id)
	d.Set("nsx_id", id)

	return resourceNsxtPolicyIpsecVpnTunnelProfileRead(d, m)
}

func resourceNsxtPolicyIpsecVpnTunnelProfileRead(d *schema.ResourceData, m interface{}) error {
	connector := getPolicyConnector(m)
	id := d.Id()
	if id == "" {
		return fmt.Errorf("Error obtaining IpsecVpnTunnelProfile ID")
	}

	var obj model.IPSecVpnTunnelProfile
	client := infra.NewDefaultIpsecVpnTunnelProfilesClient(connector)
	var err error
	obj, err = client.Get(id)
	if err != nil {
		return handleReadError(d, "IpsecVpnTunnelProfile", id, err)
	}
	d.Set("display_name", obj.DisplayName)
	d.Set("description", obj.Description)
	setPolicyTagsInSchema(d, obj.Tags)
	d.Set("nsx_id", id)
	d.Set("path", obj.Path)
	d.Set("revision", obj.Revision)
	return nil
}

func resourceNsxtPolicyIpsecVpnTunnelProfileUpdate(d *schema.ResourceData, m interface{}) error {
	connector := getPolicyConnector(m)

	id := d.Id()
	if id == "" {
		return fmt.Errorf("Error obtaining IpsecVpnTunnelProfile ID")
	}
	displayName := d.Get("display_name").(string)
	description := d.Get("description").(string)
	DhGroups := getStringListFromSchemaSet(d, "dh_groups")
	DigestAlgorithms := getStringListFromSchemaSet(d, "digest_algorithms")
	EncryptionAlgorithms := getStringListFromSchemaSet(d, "encryption_algorithms")
	obj := model.IPSecVpnTunnelProfile{
		DisplayName:          &displayName,
		Description:          &description,
		DhGroups:             DhGroups,
		DigestAlgorithms:     DigestAlgorithms,
		EncryptionAlgorithms: EncryptionAlgorithms,
	}
	var err error
	client := infra.NewDefaultIpsecVpnTunnelProfilesClient(connector)
	err = client.Patch(id, obj)

	if err != nil {
		return handleUpdateError("IpsecVpnTunnelProfile", id, err)
	}
	d.SetId(id)
	d.Set("nsx_id", id)
	return resourceNsxtPolicyIpsecVpnTunnelProfileRead(d, m)

}

func resourceNsxtPolicyIpsecVpnTunnelProfileDelete(d *schema.ResourceData, m interface{}) error {
	id := d.Id()
	if id == "" {
		return fmt.Errorf("Error obtaining IpsecVpnTunnelProfile ID")
	}

	connector := getPolicyConnector(m)
	var err error
	client := infra.NewDefaultIpsecVpnTunnelProfilesClient(connector)
	err = client.Delete(id)

	if err != nil {
		return handleDeleteError("IpsecVpnTunnelProfile", id, err)
	}

	return nil
}
