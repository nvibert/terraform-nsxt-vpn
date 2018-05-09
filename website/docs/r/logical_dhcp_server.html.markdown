---
layout: "nsxt"
page_title: "NSXT: nsxt_logical_dhcp_server"
sidebar_current: "docs-nsxt-resource-logical-dhcp-server"
description: |-
  Provides a resource to configure logical dhcp server on NSX-T manager
---

# nsxt_logical_dhcp_server

Provides a resource to configure logical dhcp server on NSX-T manager

## Example Usage

```hcl
data "nsxt_edge_cluster" "edgecluster" {
  display_name = "edgecluster1"
}

resource "nsxt_dhcp_server_profile" "serverprofile" {
  edge_cluster_id = "${data.nsxt_edge_cluster.edgecluster.id}"
}

resource "nsxt_logical_dhcp_server" "logical_dhcp_server" {
  display_name     = "logical_dhcp_server"
  description      = "logical_dhcp_server provisioned by Terraform"
  dhcp_profile_id  = "${nsxt_dhcp_server_profile.PRF.id}"
  dhcp_server_ip   = "1.1.1.10/24"
  gateway_ip       = "1.1.1.20"
  domain_name      = "abc.com"
  dns_name_servers = ["5.5.5.5"]

  dhcp_option_121 {
    network  = "6.6.6.6/24"
    next_hop = "1.1.1.21"
  }

  dhcp_generic_option {
    code = "119"
    values = ["abc"]
  }

  tag = {
    scope = "color"
    tag   = "red"
  }

}
```

## Argument Reference

The following arguments are supported:

* `display_name` - (Optional) The display name of this resource. Defaults to ID if not set.
* `description` - (Optional) Description of this resource.
* `dhcp_profile_id` - (Required) DHCP profile uuid.
* `dhcp_server_ip` - (Required) DHCP server ip in cidr format.
* `gateway_ip` - (Required) Gateway IP.
* `domain_name` - (Optional) Domain name.
* `dns_name_servers` - (Optional) DNS IPs.
* `dhcp_option_121` - (Optional) DHCP classless static routes. Each with a cidr network and next hop/
* `dhcp_generic_option` - (Optional) Generic DHCP options. Each with DHCP option code [0-255], and a list of values.
* `tag` - (Optional) A list of scope + tag pairs to associate with this logical dhcp server.


## Attributes Reference

In addition to arguments listed above, the following attributes are exported:

* `id` - ID of the logical_dhcp_server.
* `revision` - Indicates current revision number of the object as seen by NSX-T API server. This attribute can be useful for debugging.
* `attached_logical_port_id` - ID of the attached logical port.


## Importing

An existing logical dhcp server can be [imported][docs-import] into this resource, via the following command:

[docs-import]: /docs/import/index.html

```
terraform import nsxt_logical_dhcp_server.logical_dhcp_server UUID
```

The above would import the logical dhcp server named `logical_dhcp_server` with the nsx id `UUID`