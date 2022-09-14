package main

import spdx22JSON "sigs.k8s.io/bom/pkg/spdx/json/v2.2.2"

func mergeCreationInfo(bomByTools map[string]spdx22JSON.Document) spdx22JSON.CreationInfo {
	ret := spdx22JSON.CreationInfo{}
	for _, bom := range bomByTools {
		ret.Creators = append(ret.Creators, bom.CreationInfo.Creators...)
		if ret.LicenseListVersion < bom.CreationInfo.LicenseListVersion {
			ret.LicenseListVersion = bom.CreationInfo.LicenseListVersion
		}
	}
	return ret
}

// func createPackageIndex(bomByTools map[string]spdx22JSON.Document) {
// 	packagesByNameVersion := make(map[string][]spdx22JSON.Package)
// 	for _, bom := range bomByTools{
// 		for _, package := range bom.Packages {
// 			packapackagesByNameVersion[
// 				package
// 			]
// 		}
// 	}
// }
