package kinesis

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/kinesis"
)

func getStreams(ctx parser.FileContext) (streams []kinesis.Stream) {

	streamResources := ctx.GetResourcesByType("AWS::Kinesis::Stream")

	for _, r := range streamResources {

		stream := kinesis.Stream{
			Metadata: r.Metadata(),
			Encryption: kinesis.Encryption{
				Metadata: r.Metadata(),
				Type:     types.StringDefault("KMS", r.Metadata()),
				KMSKeyID: types.StringDefault("", r.Metadata()),
			},
		}

		if prop := r.GetProperty("StreamEncryption"); prop.IsNotNil() {
			stream.Encryption = kinesis.Encryption{
				Metadata: prop.Metadata(),
				Type:     prop.GetStringProperty("EncryptionType", "KMS"),
				KMSKeyID: prop.GetStringProperty("KeyId"),
			}
		}

		streams = append(streams, stream)
	}

	return streams
}
