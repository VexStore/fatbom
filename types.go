//go:generate stringer -type=BomTool
package main

import spdx22JSON "sigs.k8s.io/bom/pkg/spdx/json/v2.2.2"

type BomTool int

const (
	Syft BomTool = iota
	K8Bom
	SpdxBom
	MsBom
)

const (
	SyftImageURL  string = "docker.io/anchore/syft:v0.59.0"
	K8BomImageURL string = "docker.io/sbs2001/k8s_bom:v0.3.1"
	MSBomURL      string = "ghcr.io/sbs2001/ms_sbom:v0.0.3"
	SpdxImageURL  string = "docker.io/spdx/spdx-sbom-generator:v0.0.14"
)

type SpdxPackageExternalRef struct {
	spdx22JSON.ExternalRef
	Comment string `json:"comment,omitempty"`
}

type SpdxPackage struct {
	spdx22JSON.Package
	ExternalRefs []SpdxPackageExternalRef `json:"externalRefs,omitempty"`
}

type SpdxDocument struct {
	spdx22JSON.Document
	Packages []SpdxPackage `json:"packages"`
}
