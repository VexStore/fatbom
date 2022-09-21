package main

import (
	"fmt"

	spdx22JSON "sigs.k8s.io/bom/pkg/spdx/json/v2.2.2"
)

type ExternalRefKey struct {
	Type    string
	Locator string
}

type PackageWithBomTool struct {
	BomTool string
	Package SpdxPackage
}

func mergeCreationInfo(bomByTools map[string]SpdxDocument) spdx22JSON.CreationInfo {
	ret := spdx22JSON.CreationInfo{}
	for _, bom := range bomByTools {
		ret.Creators = append(ret.Creators, bom.CreationInfo.Creators...)
		if ret.LicenseListVersion < bom.CreationInfo.LicenseListVersion {
			ret.LicenseListVersion = bom.CreationInfo.LicenseListVersion
		}
	}
	return ret
}

// FIXME: Once, Spdx bom generator provides purls, the key of this index should be purls instead of name+version
func createPackageIndex(bomByTools map[string]SpdxDocument) map[string][]PackageWithBomTool {
	pbtByNameVersion := make(map[string][]PackageWithBomTool)
	for tool, bom := range bomByTools {
		for _, p := range bom.Packages {
			key := fmt.Sprintf("%s-%s", p.Name, p.Version)
			pbt := PackageWithBomTool{Package: p, BomTool: tool}
			pbtByNameVersion[key] = append(pbtByNameVersion[key], pbt)
		}
	}
	return pbtByNameVersion
}

func mergePackages(bomByTools map[string]SpdxDocument) []SpdxPackage {
	idx := createPackageIndex(bomByTools)
	ret := make([]SpdxPackage, len(idx))
	i := 0
	for _, pbts := range idx {
		p := pbts[0].Package
		extRefSet := make(map[ExternalRefKey]SpdxPackageExternalRef)
		for _, pbt := range pbts {
			for _, ref := range pbt.Package.ExternalRefs {
				key := ExternalRefKey{Type: ref.Type, Locator: ref.Locator}
				ref.Comment = extRefSet[key].Comment + fmt.Sprintf("Found by %s Tool. ", pbt.BomTool)
				extRefSet[key] = ref
			}
		}
		p.ExternalRefs = []SpdxPackageExternalRef{}
		for _, ref := range extRefSet {
			p.ExternalRefs = append(p.ExternalRefs, ref)
		}
		ret[i] = p
		i++
	}
	return ret
}

func Merge(bomByTools map[string]SpdxDocument) SpdxDocument {
	ret := SpdxDocument{}
	ret.CreationInfo = mergeCreationInfo(bomByTools)
	ret.Packages = mergePackages(bomByTools)
	return ret
}
