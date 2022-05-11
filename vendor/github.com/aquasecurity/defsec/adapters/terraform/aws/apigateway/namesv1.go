package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func adaptDomainNamesV1(modules terraform.Modules) []apigateway.DomainName {

	var domainNames []apigateway.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_api_gateway_domain_name") {
			domainName := apigateway.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
				Version:        types.Int(1, nameBlock.GetMetadata()),
				SecurityPolicy: nameBlock.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", nameBlock),
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}
