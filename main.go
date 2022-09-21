package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/schollz/progressbar/v3"
)

const (
	SyftImageURL  string = "docker.io/anchore/syft"
	K8BomImageURL string = "docker.io/sbs2001/k8s_bom:latest"
	MSBomURL      string = "ghcr.io/sbs2001/ms_sbom:v0.0.3"
	SpdxImageURL  string = "docker.io/spdx/spdx-sbom-generator"
)

func main() {
	dirToScan := flag.String("s", "", "directory to scan")
	pathToMerged := flag.String("p", "", "path to bom by tools")
	flag.Parse()

	if pathToMerged != nil && *pathToMerged != "" {
		fmt.Println(*pathToMerged)
		fmt.Println(*dirToScan)
		fullPath, err := filepath.Abs(*pathToMerged)
		if err != nil {
			panic(err)
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			panic(err)
		}
		z := make(map[string]SpdxDocument)
		if err := json.Unmarshal(data, &z); err != nil {
			panic(err)
		}
		doc := Merge(z)
		content, err := json.MarshalIndent(doc, "\t", "\t")
		if err := os.WriteFile("full_merged.json", content, 0666); err != nil {
			panic(err)
		}
		return
	}
	fullPath, err := filepath.Abs(*dirToScan)
	if err != nil {
		panic(err)
	}

	scanResultsByTool := make(map[string]SpdxDocument)

	wg := sync.WaitGroup{}
	wg.Add(4)
	// microsoft bom generator
	go func() {
		bar := progressbar.Default(-1)
		defer bar.Finish()
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
		t := SpdxDocument{}
		if err := json.Unmarshal(data, &t); err != nil {
			panic(err)
		}
		scanResultsByTool[MsBom.String()] = t
	}()

	//spdx generator
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
		merged := SpdxDocument{}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			outFile := filepath.Join(tmpDir, entry.Name())
			doc := SpdxDocument{}
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
		scanResultsByTool[SpdxBom.String()] = merged
	}()

	// // // k8s BOM generator
	go func() {
		defer wg.Done()
		k8BomOut, err := exec.Command("docker", "run", "-v", fullPath+":"+"/scan", K8BomImageURL, "generate", "/scan", "--format", "json").Output()
		if err != nil {
			panic(err)
		}
		k8Bom := SpdxDocument{}
		if err := json.Unmarshal(k8BomOut, &k8Bom); err != nil {
			panic(err)
		}
		scanResultsByTool[K8Bom.String()] = k8Bom
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
		syftRes := SpdxDocument{}
		json.Unmarshal(syftBomOut, &syftRes)
		scanResultsByTool[Syft.String()] = syftRes
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
