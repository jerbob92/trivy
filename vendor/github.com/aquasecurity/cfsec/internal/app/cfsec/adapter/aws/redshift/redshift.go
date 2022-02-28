package redshift

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/redshift"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result redshift.Redshift) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Clusters = getClusters(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result

}
