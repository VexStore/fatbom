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
