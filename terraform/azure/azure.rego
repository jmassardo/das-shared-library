package global.shared.terraform.azure

# These aren't approved ports
badPorts = {"22", "80", "3389"}

# filter down the input for the specific items we want to test
resourcePorts := {p | c = input.resource_changes[_]; p = c.change.after.security_rule[_].destination_port_range}
StorageRefImgVer := {i | c = input.resource_changes[_]; i = c.change.after.storage_image_reference[_].version}
