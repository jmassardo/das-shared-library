package global.shared.terraform.azure

# These aren't approved ports
badPorts = {"22", "80", "3389"}

# filter down the input for the specific items we want to test
resourcePorts := {p | c = input.resource_changes[_]; p = c.change.after.security_rule[_].destination_port_range}
StorageRefImgVer := {i | c = input.resource_changes[_]; i = c.change.after.storage_image_reference[_].version}

deny[decision] {
  StorageRefImgVer["latest"]
    msg := "`Latest` image versions are not allowed"
    decision := {
      "allowed": false,
      "message": msg
    }
}
deny[decision] {
  p := badPorts & resourcePorts
  count(p) > 0
  msg := sprintf("Port `%v` is not an approved port.", [p[_]])
  decision := {
      "allowed": false,
      "message": msg
    }
}

validate = decision {
    count(deny) > 0
    messages := {i | c = deny[_]; i = c.message}
    msg := concat(",", messages)
    decision := {
      "allowed": false,
      "message": msg
    } 
} else = response {
    true
}

response = {
	"allowed": true,
    "message": "No policy violations detected."
}