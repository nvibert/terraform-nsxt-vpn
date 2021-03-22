/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: MPL-2.0 */

package nsxt

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/bindings"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/data"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/protocol/client"
	ipsec_vpn_services "github.com/vmware/vsphere-automation-sdk-go/services/nsxt/infra/tier_0s/locale_services/ipsec_vpn_services"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/model"
)

var IPSecVpnSession_RESOURCE_TYPE = []string{
	model.IPSecVpnSession_RESOURCE_TYPE_POLICYBASEDIPSECVPNSESSION,
	model.IPSecVpnSession_RESOURCE_TYPE_ROUTEBASEDIPSECVPNSESSION,
}

var IPSecVpnSession_AUTHENTICATION_MODE = []string{
	model.IPSecVpnSession_AUTHENTICATION_MODE_PSK,
	model.IPSecVpnSession_AUTHENTICATION_MODE_CERTIFICATE,
}

var IPSecVpnSession_CONNECTION_INITIATION_MODE = []string{
	model.IPSecVpnSession_CONNECTION_INITIATION_MODE_INITIATOR,
	model.IPSecVpnSession_CONNECTION_INITIATION_MODE_RESPOND_ONLY,
	model.IPSecVpnSession_CONNECTION_INITIATION_MODE_ON_DEMAND,
}
var IPSecVpnSession_COMPLIANCE_SUITE = []string{
	model.IPSecVpnSession_COMPLIANCE_SUITE_CNSA,
	model.IPSecVpnSession_COMPLIANCE_SUITE_SUITE_B_GCM_128,
	model.IPSecVpnSession_COMPLIANCE_SUITE_SUITE_B_GCM_256,
	model.IPSecVpnSession_COMPLIANCE_SUITE_PRIME,
	model.IPSecVpnSession_COMPLIANCE_SUITE_FOUNDATION,
	model.IPSecVpnSession_COMPLIANCE_SUITE_FIPS,
	model.IPSecVpnSession_COMPLIANCE_SUITE_NONE,
}

func resourceNsxtPolicyIPSecVpnSession() *schema.Resource {
	return &schema.Resource{
		Create: resourceNsxtPolicyIPSecVpnSessionCreate,
		Read:   resourceNsxtPolicyIPSecVpnSessionRead,
		Update: resourceNsxtPolicyIPSecVpnSessionUpdate,
		Delete: resourceNsxtPolicyIPSecVpnSessionDelete,
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
				Type:         schema.TypeString,
				Description:  " A Policy Based VPN requires to define protect rules that match local and peer subnets. IPSec security associations is negotiated for each pair of local and peer subnet. A Route Based VPN is more flexible, more powerful and recommended over policy based VPN. IP Tunnel port is created and all traffic routed via tunnel port is protected. Routes can be configured statically or can be learned through BGP. A route based VPN is must for establishing redundant VPN session to remote site.",
				ValidateFunc: validation.StringInSlice(IPSecVpnSession_RESOURCE_TYPE, false),
				Optional:     true,
			},
			"compliance_suite": {
				Type:         schema.TypeString,
				Description:  "Connection initiation mode used by local endpoint to establish ike connection with peer site. INITIATOR - In this mode local endpoint initiates tunnel setup and will also respond to incoming tunnel setup requests from peer gateway. RESPOND_ONLY - In this mode, local endpoint shall only respond to incoming tunnel setup requests. It shall not initiate the tunnel setup. ON_DEMAND - In this mode local endpoint will initiate tunnel creation once first packet matching the policy rule is received and will also respond to incoming initiation request.",
				ValidateFunc: validation.StringInSlice(IPSecVpnSession_COMPLIANCE_SUITE, false),
				Optional:     true,
			},
			"connection_initiation_mode": {
				Type:         schema.TypeString,
				Description:  "Compliance suite.",
				ValidateFunc: validation.StringInSlice(IPSecVpnSession_CONNECTION_INITIATION_MODE, false),
				Optional:     true,
			},
			"authentication_mode": {
				Type:         schema.TypeString,
				Description:  "Peer authentication mode. PSK - In this mode a secret key shared between local and peer sites is to be used for authentication. The secret key can be a string with a maximum length of 128 characters. CERTIFICATE - In this mode a certificate defined at the global level is to be used for authentication.",
				ValidateFunc: validation.StringInSlice(IPSecVpnSession_AUTHENTICATION_MODE, false),
				Optional:     true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Enable/Disable IPSec VPN session.",
				Optional:    true,
				Default:     true,
			},
			"dpd_profile_path": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Dead Peer Detection (DPD) profile. Default is set to system default profile.",
				Optional:    true,
				Default:     "/infra/ipsec-vpn-dpd-profiles/nsx-default-l3vpn-dpd-profile",
			},
			"psk": {
				Type:        schema.TypeString,
				Description: "IPSec Pre-shared key. Maximum length of this field is 128 characters.",
				Optional:    true,
			},
			"peer_id": {
				Type:        schema.TypeString,
				Description: "Peer ID to uniquely identify the peer site. The peer ID is the public IP address of the remote device terminating the VPN tunnel. When NAT is configured for the peer, enter the private IP address of the peer.",
				Optional:    true,
			},
			"peer_address": {
				Type:        schema.TypeString,
				Description: "Public IPV4 address of the remote device terminating the VPN connection.",
				Optional:    true,
			},
			"tunnel_profile_path": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Tunnel profile to be used. Default is set to system default profile.",
				Required:    true,
			},
			"local_endpoint_path": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Local endpoint.",
				Optional:    true,
			},
			"ike_profile_path": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Local endpoint.",
				Optional:    true,
			},
			"tier0_id": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Local endpoint.",
				Optional:    true,
				Default:     "vmc",
			},
			"locale_service": {
				Type:        schema.TypeString,
				Description: "Local_service",
				Optional:    true,
				Default:     "default",
			},
			"service_id": {
				Type:        schema.TypeString,
				Description: "Policy path referencing Local endpoint.",
				Optional:    true,
				Default:     "default",
			},
			"subnets": {
				Type:        schema.TypeList,
				Description: "IP Tunnel interfaces.",
				Optional:    true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validateSingleIP(),
				},
			},
			"prefix_length": {
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 255),
				Description:  "Authentication secret key id for MD5 auth mode",
			},
		},
	}
}

func resourceNsxtPolicyIPSecVpnSessionExists(tier0IdParam string, localeServiceIdParam string, serviceIdParam string, sessionIdParam string, connector *client.RestConnector, isGlobalManager bool) (bool, error) {
	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)
	_, err := client.Get(tier0IdParam, localeServiceIdParam, serviceIdParam, sessionIdParam)

	if err == nil {
		return true, nil
	}

	if isNotFoundError(err) {
		return false, nil
	}

	return false, logAPIError("Error retrieving resource", err)

}

func getTunnelInterfaceSubnetList(d *schema.ResourceData) []model.TunnelInterfaceIPSubnet {
	subnets := interface2StringList(d.Get("subnets").([]interface{}))
	var TunnelInterfaceSubnetList []model.TunnelInterfaceIPSubnet
	for _, subnet := range subnets {
		result := strings.Split(subnet, "/")
		var ipAddresses []string
		ipAddresses = append(ipAddresses, result[0])
		prefix, _ := strconv.Atoi(result[1])
		prefix64 := int64(prefix)
		TunnelinterfaceSubnet := model.TunnelInterfaceIPSubnet{
			IpAddresses:  ipAddresses,
			PrefixLength: &prefix64,
		}
		TunnelInterfaceSubnetList = append(TunnelInterfaceSubnetList, TunnelinterfaceSubnet)
	}

	return TunnelInterfaceSubnetList
}

func getIPSecVPNSessionFromSchema(d *schema.ResourceData) (*data.StructValue, error) {
	converter := bindings.NewTypeConverter()
	converter.SetMode(bindings.REST)

	Psk := d.Get("psk").(string)
	log.Println(Psk)
	PeerId := d.Get("peer_id").(string)
	log.Println(PeerId)
	PeerAddress := d.Get("peer_address").(string)
	log.Println(PeerAddress)
	log.Println("########################################################1")
	displayName := d.Get("display_name").(string)
	log.Println(displayName)
	log.Println("########################################################2")
	description := d.Get("description").(string)
	log.Println(description)
	log.Println("########################################################3")
	IkeProfilePath := d.Get("ike_profile_path").(string)
	log.Println(IkeProfilePath)
	log.Println("########################################################4")
	ResourceType := d.Get("vpn_type").(string)
	log.Println(ResourceType)
	log.Println("########################################################5")
	LocalEndpointVar := d.Get("local_endpoint_path").(string)
	var LocalEndpointPath string
	if LocalEndpointVar == "Private" {
		LocalEndpointPath = "/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints/Private-IP1"
	} else {
		LocalEndpointPath = "/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints/Public-IP1"
	}
	log.Println(LocalEndpointVar)
	log.Println(LocalEndpointPath)
	log.Println("########################################################6a")
	DpdProfilePath := d.Get("dpd_profile_path").(string)
	log.Println(DpdProfilePath)
	TunnelProfilePath := d.Get("tunnel_profile_path").(string)
	log.Println(TunnelProfilePath)
	log.Println("########################################################6b")
	ConnectionInitiationMode := d.Get("connection_initiation_mode").(string)
	AuthenticationMode := d.Get("authentication_mode").(string)
	ComplianceSuite := d.Get("compliance_suite").(string)
	log.Println(ComplianceSuite)
	log.Println("########################################################7")
	Prefix_length := int64(d.Get("prefix_length").(int))
	log.Println(Prefix_length)
	log.Println("########################################################7.1")
	Enabled := d.Get("enabled").(bool)
	log.Println(Enabled)
	log.Println("########################################################8")
	//TunnelInterface := getStringListFromSchemaSet(d, "subnets")
	subnet_ts := d.Get("subnets")
	log.Println(subnet_ts)
	TunnelInterface := interfaceListToStringList(d.Get("subnets").([]interface{}))

	log.Println("########################################################9")
	log.Println(Prefix_length)
	log.Println(TunnelInterface)
	log.Println("########################################################10")

	var IPSubnets []model.TunnelInterfaceIPSubnet
	log.Println(IPSubnets)
	log.Println("########################################################10.1")
	IPSubnet := model.TunnelInterfaceIPSubnet{
		IpAddresses:  TunnelInterface,
		PrefixLength: &Prefix_length,
	}
	log.Println("########################################################10.2")
	IPSubnets = append(IPSubnets, IPSubnet)
	log.Println(IPSubnets)
	log.Println("########################################################10.3")
	var VTIlist []model.IPSecVpnTunnelInterface
	log.Println("########################################################10.4")
	vti := model.IPSecVpnTunnelInterface{
		IpSubnets: IPSubnets,
	}
	log.Println("########################################################10.5")
	log.Println(VTIlist)
	log.Println("########################################################10.6")
	VTIlist = append(VTIlist, vti)
	log.Println(VTIlist)
	log.Println("########################################################10.6")

	route_obj := model.RouteBasedIPSecVpnSession{
		DisplayName:              &displayName,
		Description:              &description,
		IkeProfilePath:           &IkeProfilePath,
		LocalEndpointPath:        &LocalEndpointPath,
		TunnelProfilePath:        &TunnelProfilePath,
		DpdProfilePath:           &DpdProfilePath,
		ConnectionInitiationMode: &ConnectionInitiationMode,
		ComplianceSuite:          &ComplianceSuite,
		AuthenticationMode:       &AuthenticationMode,
		ResourceType:             ResourceType,
		Enabled:                  &Enabled,
		TunnelInterfaces:         VTIlist,
		PeerAddress:              &PeerAddress,
		PeerId:                   &PeerId,
		Psk:                      &Psk,
	}
	log.Println(route_obj)
	log.Println("########################################################10.7")
	dataValue, err := converter.ConvertToVapi(route_obj, model.RouteBasedIPSecVpnSessionBindingType())
	log.Println("########################################################10.7")
	if err != nil {
		return nil, err[0]
	}

	return dataValue.(*data.StructValue), nil
}

func resourceNsxtPolicyIpsecVpnIkeSessionExists(id string, connector *client.RestConnector, isGlobalManager bool) (bool, error) {
	var err error
	Tier0ID := d.Get("tier0_id").(string)
	LocaleService := d.Get("locale_service").(string)
	ServiceID := d.Get("service_id").(string)

	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)
	_, err = client.Get(Tier0ID, LocaleService, ServiceID, id)

	if err == nil {
		return true, nil
	}

	if isNotFoundError(err) {
		return false, nil
	}

	return false, logAPIError("Error retrieving resource", err)
}

func resourceNsxtPolicyIPSecVpnSessionCreate(d *schema.ResourceData, m interface{}) error {

	Tier0ID := d.Get("tier0_id").(string)
	LocaleService := d.Get("locale_service").(string)
	ServiceID := d.Get("service_id").(string)

	// Initialize resource Id and verify this ID is not yet used
	id := newUUID()

	connector := getPolicyConnector(m)

	obj, err := getIPSecVPNSessionFromSchema(d)
	if err != nil {
		return err
	}

	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)

	// Create the resource using PATCH
	log.Printf("[INFO] Creating IPSecVpnSession with ID %s", id)

	err2 := client.Patch(Tier0ID, LocaleService, ServiceID, id, obj)

	log.Println("########################################################")
	if err2 != nil {
		return handleCreateError("IPSecVpnSession", id, err)
	}

	d.SetId(id)
	d.Set("nsx_id", id)

	return resourceNsxtPolicyIPSecVpnSessionRead(d, m)
}

func resourceNsxtPolicyIPSecVpnSessionRead(d *schema.ResourceData, m interface{}) error {
	connector := getPolicyConnector(m)
	converter := bindings.NewTypeConverter()
	converter.SetMode(bindings.REST)

	id := d.Id()
	log.Println(id)
	if id == "" {
		return fmt.Errorf("Error obtaining IPSecVpnSession ID")
	}

	Tier0ID := d.Get("tier0_id").(string)
	LocaleService := d.Get("locale_service").(string)
	ServiceID := d.Get("service_id").(string)

	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)

	obj, err := client.Get(Tier0ID, LocaleService, ServiceID, id)

	if err != nil {
		if isNotFoundError(err) {
			d.SetId("")
			log.Printf("[DEBUG] VPNSession %s not found", id)
			return nil
		}
		return handleReadError(d, "VPN Session", id, err)
	}

	interface_vpn, errs := converter.ConvertToGolang(obj, model.RouteBasedIPSecVpnSessionBindingType())
	if len(errs) > 0 {
		return fmt.Errorf("Error converting VPN Session %s", errs[0])
	}
	blockVPN := interface_vpn.(model.RouteBasedIPSecVpnSession)

	d.Set("display_name", blockVPN.DisplayName)
	d.Set("description", blockVPN.Description)
	setPolicyTagsInSchema(d, blockVPN.Tags)
	d.Set("nsx_id", blockVPN.Id)
	d.Set("path", blockVPN.Path)
	d.Set("revision", blockVPN.Revision)

	return nil
}

func resourceNsxtPolicyIPSecVpnSessionUpdate(d *schema.ResourceData, m interface{}) error {
	connector := getPolicyConnector(m)

	id := d.Id()
	if id == "" {
		return fmt.Errorf("Error obtaining IPSecVpnSession ID")
	}

	Tier0ID := d.Get("tier0_id").(string)
	LocaleService := d.Get("locale_service").(string)
	ServiceID := d.Get("service_id").(string)

	obj, err := getIPSecVPNSessionFromSchema(d)
	if err != nil {
		return err
	}

	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)

	// Create the resource using PATCH
	log.Printf("[INFO] Creating IPSecVpnSession with ID %s", id)

	err2 := client.Patch(Tier0ID, LocaleService, ServiceID, id, obj)

	if err2 != nil {
		return handleUpdateError("IPSecVpnSession", id, err)
	}
	d.SetId(id)
	d.Set("nsx_id", id)
	return resourceNsxtPolicyIPSecVpnSessionRead(d, m)

}

func resourceNsxtPolicyIPSecVpnSessionDelete(d *schema.ResourceData, m interface{}) error {
	id := d.Id()
	if id == "" {
		return fmt.Errorf("Error obtaining IPSecVpnSession ID")
	}
	Tier0ID := d.Get("tier0_id").(string)
	LocaleService := d.Get("locale_service").(string)
	ServiceID := d.Get("service_id").(string)

	connector := getPolicyConnector(m)
	var err error
	client := ipsec_vpn_services.NewDefaultSessionsClient(connector)
	err = client.Delete(Tier0ID, LocaleService, ServiceID, id)

	if err != nil {
		return handleDeleteError("IPSecVpnSession", id, err)
	}

	return nil
}
