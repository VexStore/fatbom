package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	spdx22JSON "sigs.k8s.io/bom/pkg/spdx/json/v2.2.2"
)

const (
	SyftImageURL  string = "docker.io/anchore/syft"
	K8BomImageURL string = "docker.io/sbs2001/k8s_bom:latest"
	MSBomURL      string = "ghcr.io/sbs2001/ms_sbom:v0.0.2"
	SpdxImageURL  string = "docker.io/spdx/spdx-sbom-generator"
)

// var SpdxToolSlugToPurlType = map[string]string{
// 	"cargo":      "cargo",
// 	"composer":   "composer",
// 	"bundler":    "gem",
// 	"go-mod":     "golang",
// 	"Java-Maven": "maven",
// 	"npm":        "npm",
// 	"nuget":      "nuget",
// 	"pipenv":     "pypi",
// 	"poetry":     "pypi",
// 	"pyenv":      "pypi",
// 	"swift":      "swift",
// 	"yarn":       "npm",
// }

// func ecosystemFromSpdxFileName(fileName string) string {
// 	parts := strings.Split(fileName, ".")
// 	return SpdxToolSlugToPurlType[parts[0][4:]]
// }

func main() {
	dirToScan := flag.String("s", "./", "directory to scan")
	flag.Parse()
	fullPath, err := filepath.Abs(*dirToScan)
	if err != nil {
		panic(err)
	}

	scanResultsByTool := make(map[string]spdx22JSON.Document)

	wg := sync.WaitGroup{}
	wg.Add(4)
	// microsoft bom generator
	go func() {
		defer wg.Done()
		tmpDir, err := os.MkdirTemp(os.TempDir(), "ubom")
		if err != nil {
			panic(tmpDir)
		}
		_, err = exec.Command("docker", "run", "-t",
			"-v", fullPath+":"+"/scan",
			"-v", tmpDir+":"+tmpDir,
			MSBomURL, "generate", "-b", "/scan",
			"-bc", "/scan", "-pn", "blah",
			"-nsb", "https://companyName.com/teamName",
			"-pv", "0.0.1", "-D", "true", "-V", "Fatal",
			"-m", tmpDir,
		).CombinedOutput()

		if err != nil {
			panic(err)
		}
		manifestPath := filepath.Join(tmpDir, "_manifest", "spdx_2.2", "manifest.spdx.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			panic(err)
		}
		t := spdx22JSON.Document{}
		if err := json.Unmarshal(data, &t); err != nil {
			panic(err)
		}
		scanResultsByTool["msbom"] = t
	}()

	go func() {
		defer wg.Done()
		tmpDir, err := os.MkdirTemp(os.TempDir(), "ubom")
		if err != nil {
			panic(tmpDir)
		}
		_, err = exec.Command(
			"docker", "run", "-v", fullPath+":"+"/scan",
			"-v", tmpDir+":"+tmpDir,
			SpdxImageURL, "-p", "/scan",
			"-o", tmpDir,
			"--format", "json",
		).CombinedOutput()

		if err != nil {
			panic(err)
		}

		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			panic(err)
		}
		merged := spdx22JSON.Document{}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			outFile := filepath.Join(tmpDir, entry.Name())
			doc := spdx22JSON.Document{}
			data, err := os.ReadFile(outFile)
			if err != nil {
				panic(err)
			}
			json.Unmarshal(data, &doc)
			merged.Files = append(merged.Files, doc.Files...)
			merged.Packages = append(merged.Packages, doc.Packages...)
			merged.Relationships = append(merged.Relationships, doc.Relationships...)
		}
		if err != nil {
			panic(err)
		}
		scanResultsByTool["spdx_tool"] = merged
	}()

	// // // k8s BOM generator
	go func() {
		defer wg.Done()
		k8BomOut, err := exec.Command("docker", "run", "-v", fullPath+":"+"/scan", K8BomImageURL, "generate", "/scan", "--format", "json").Output()
		if err != nil {
			panic(err)
		}
		k8Bom := spdx22JSON.Document{}
		if err := json.Unmarshal(k8BomOut, &k8Bom); err != nil {
			panic(err)
		}
		scanResultsByTool["k8_bom"] = k8Bom
	}()

	// // syft BOM generator
	go func() {
		defer wg.Done()
		syftBomOut, err := exec.Command(
			"docker", "run", "-v",
			fullPath+":"+"/scan", SyftImageURL,
			"packages",
			"dir:/scan", "-o", "spdx-json").CombinedOutput()
		if err != nil {
			panic(err)
		}
		syftRes := spdx22JSON.Document{}
		json.Unmarshal(syftBomOut, &syftRes)
		scanResultsByTool["syft"] = syftRes
	}()

	fmt.Println("Triggered all scans")
	wg.Wait()

	data, err := json.Marshal(scanResultsByTool)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("merged_bom.json", data, 0666); err != nil {
		panic(err)
	}

}
