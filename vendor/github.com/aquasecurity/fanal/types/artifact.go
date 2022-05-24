package types

import (
	"time"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type OS struct {
	Family string
	Name   string
	Eosl   bool `json:"EOSL,omitempty"`
}

type Repository struct {
	Family  string `json:",omitempty"`
	Release string `json:",omitempty"`
}

type Layer struct {
	Digest string `json:",omitempty"`
	DiffID string `json:",omitempty"`
}

type Package struct {
	ID         string `json:",omitempty"`
	Name       string `json:",omitempty"`
	Version    string `json:",omitempty"`
	Release    string `json:",omitempty"`
	Epoch      int    `json:",omitempty"`
	Arch       string `json:",omitempty"`
	SrcName    string `json:",omitempty"`
	SrcVersion string `json:",omitempty"`
	SrcRelease string `json:",omitempty"`
	SrcEpoch   int    `json:",omitempty"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat

	Indirect bool   `json:",omitempty"`
	License  string `json:",omitempty"`
	Layer    Layer  `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`
}

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string `json:",omitempty"`
	Nvr         string   `json:",omitempty"`
	Arch        string   `json:",omitempty"`
}

func (pkg *Package) Empty() bool {
	return pkg.Name == "" || pkg.Version == ""
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages []Package
}

type Application struct {
	// e.g. bundler and pipenv
	Type string

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Libraries is a list of lang-specific packages
	Libraries []Package

	// Dependencies represents dependency graph
	Dependencies []godeptypes.Dependency `json:",omitempty"`
}

type File struct {
	Type    string
	Path    string
	Content []byte
}

// ArtifactType represents a type of artifact
type ArtifactType string

const (
	ArtifactContainerImage   ArtifactType = "container_image"
	ArtifactFilesystem       ArtifactType = "filesystem"
	ArtifactRemoteRepository ArtifactType = "repository"
)

// ArtifactReference represents a reference of container image, local filesystem and repository
type ArtifactReference struct {
	Name          string // image name, tar file name, directory or repository name
	Type          ArtifactType
	ID            string
	BlobIDs       []string
	ImageMetadata ImageMetadata
}

type ImageMetadata struct {
	ID          string   // image ID
	DiffIDs     []string // uncompressed layer IDs
	RepoTags    []string
	RepoDigests []string
	ConfigFile  v1.ConfigFile
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion     int
	Digest            string             `json:",omitempty"`
	DiffID            string             `json:",omitempty"`
	OS                *OS                `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	PackageInfos      []PackageInfo      `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	OpaqueDirs        []string           `json:",omitempty"`
	WhiteoutFiles     []string           `json:",omitempty"`

	// Red Hat distributions have build info per layer.
	// This information will be embedded into packages when applying layers.
	// ref. https://redhat-connect.gitbook.io/partner-guide-for-adopting-red-hat-oval-v2/determining-common-platform-enumeration-cpe
	BuildInfo *BuildInfo `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ArtifactDetail is generated by applying blobs
type ArtifactDetail struct {
	OS                *OS                `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	Packages          []Package          `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// CustomResource holds the analysis result from a custom analyzer.
// It is for extensibility and not used in OSS.
type CustomResource struct {
	Type     string
	FilePath string
	Layer    Layer
	Data     interface{}
}
