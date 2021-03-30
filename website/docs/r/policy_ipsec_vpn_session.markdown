---
subcategory: "Policy - Gateways and Routing"
layout: "nsxt"
page_title: "NSXT: nsxt_policy_ipsec_vpn_ike_session"
description: A resource to configure a IPSec VPN Ike session.
---

# nsxt_policy_ipsec_vpn_ike_session

This resource provides a method for the management of a IPSec VPN Ike session.

This resource is applicable to NSX Policy Manager and VMC.

## Example Usage

```hcl
resource "nsxt_policy_ipsec_vpn_ike_session" "test" {
    display_name      = "test"
    description       = "Terraform provisioned IPSec VPN Ike session"
    ike_profile_path    = nsxt_policy_ipsec_vpn_ike_profile.profile_ike.path
    tunnel_profile_path = nsxt_policy_ipsec_vpn_tunnel_profile.profile_tunnel.path
    enabled             = true
    locale_service      = "default"
    service_id          = "default"
    tier0_id            = "vmc"
    vpn_type            = "RouteBasedIPSecVpnSession"
    compliance_suite    = "NONE"
    subnets             = ["169.254.151.2"]
    prefix_length       = 30
    peer_address        = "12.12.12.12"
    peer_id             = "12.12.12.12"
    psk                 = "None"
}
```

## Argument Reference

The following arguments are supported:

* `display_name` - (Required) Display name of the resource.
* `description` - (Optional) Description of the resource.
* `tag` - (Optional) A list of scope + tag pairs to associate with this resource.
* `nsx_id` - (Optional) The NSX ID of this resource. If set, this ID will be used to create the resource.
* `ike_profile_path` - (Optional)    = nsxt_policy_ipsec_vpn_ike_profile.profile_ike.path
* `tunnel_profile_path` - (Optional)    tunnel_profile_path = nsxt_policy_ipsec_vpn_tunnel_profile.profile_tunnel.path
* `enabled` - (Optional)                 = true
* `locale_service` - (Optional)          = "default"
* `service_id` - (Optional)              = "default"
* `tier0_id` - (Optional)                = "vmc"
* `vpn_type` - (Optional)                = "RouteBasedIPSecVpnSession"
* `compliance_suite` - (Optional)    compliance_suite    = "NONE"
* `subnets` - (Optional)                 = ["169.254.151.2"]
* `prefix_length` - (Optional)           = 30
* `peer_address` - (Optional)    peer_address        = "12.12.12.12"
* `peer_id` - (Optional)    peer_id             = "12.12.12.12"
* `peer_id` - (Optional)    = "None"

## Attributes Reference

In addition to arguments listed above, the following attributes are exported:

* `id` - ID of the resource.
* `revision` - Indicates current revision number of the object as seen by NSX-T API server. This attribute can be useful for debugging.
* `path` - The NSX path of the policy resource.

## Importing

An existing object can be [imported][docs-import] into this resource, via the following command:

[docs-import]: /docs/import/index.html

```
terraform import nsxt_policy_ipsec_vpn_ike_session.test UUID
```

The above command imports IPSec VPN Ike session named `test` with the NSX IPSec VPN Ike session ID `UUID`.
