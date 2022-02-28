package compute

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.GoogleProvider,
		Service:   "compute",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:     "SSL policies should enforce secure versions of TLS",
			Explanation: `TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.`,
			Impact:      "Data in transit is not sufficiently secured",
			Resolution:  "Enforce a minimum TLS version of 1.2",
			BadExample: []string{`
resource "google_compute_ssl_policy" "bad_example" {
  name    = "production-ssl-policy"
  profile = "MODERN"
  min_tls_version = "TLS_1_1"
}

`},
			GoodExample: []string{`
resource "google_compute_ssl_policy" "good_example" {
  name    = "production-ssl-policy"
  profile = "MODERN"
  min_tls_version = "TLS_1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_policy#min_tls_version",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_ssl_policy",
		},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if minTlsVersionAttr := resourceBlock.GetAttribute("min_tls_version"); minTlsVersionAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for min_tls_version", resourceBlock.FullName())
			} else if minTlsVersionAttr.NotEqual("TLS_1_2") {
				set.AddResult().
					WithDescription("Resource '%s' does not have min_tls_version set to TLS_1_2", resourceBlock.FullName()).
					WithAttribute(minTlsVersionAttr)
			}
		},
	})
}
