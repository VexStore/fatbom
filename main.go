package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/sbs2001/uispinner"
	"github.com/sirupsen/logrus"
)

var cj = uispinner.New()
var DockerCmd string
var fullPathToDirToScan string

func pullDockerImageWithSpinner(imageURL string, sp *uispinner.Spinner) error {
	newSp := sp.AddSpinner(charsetWithColor(11, 34), 50*time.Millisecond).
		SetComplete(" Pulled " + imageURL).SetSuffix(" Pulling " + imageURL)
	defer newSp.Done()
	_, err := exec.Command(DockerCmd, "pull", imageURL).CombinedOutput()
	return err
}

func setDockerCmd() {
	if cmd := os.Getenv("DOCKER_CMD"); cmd != "" {
		DockerCmd = cmd
	} else {
		DockerCmd = "docker"
	}
}

func charsetWithColor(index int, color int) []string {
	ori := spinner.CharSets[index]
	colored := make([]string, len(ori))
	for i := range ori {
		colored[i] = fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, ori[i])
	}
	return colored
}

func getSpinner(during string, onComplete string) *uispinner.Spinner {
	return cj.AddSpinner(charsetWithColor(11, 34), 50*time.Millisecond).SetComplete(onComplete).SetSuffix(during)
}

func main() {
	setDockerCmd()
	dirToScan := flag.String("s", "", "directory to scan")
	pathToMerged := flag.String("p", "", "path to bom by tools")
	flag.Parse()
	if pathToMerged != nil && *pathToMerged != "" {
		fullPathToMerged, err := filepath.Abs(*pathToMerged)
		if err != nil {
			panic(err)
		}
		data, err := os.ReadFile(fullPathToMerged)
		if err != nil {
			panic(err)
		}
		z := make(map[string]SpdxDocument)
		if err := json.Unmarshal(data, &z); err != nil {
			panic(err)
		}
		doc := Merge(z)
		content, err := json.MarshalIndent(doc, "\t", "\t")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile("full_merged.json", content, 0666); err != nil {
			panic(err)
		}
		return
	}
	var err error
	fullPathToDirToScan, err = filepath.Abs(*dirToScan)
	if err != nil {
		panic(err)
	}
	cj.Start()
	scanResultsByTool := make(map[string]SpdxDocument)

	wg := sync.WaitGroup{}
	wg.Add(4)

	logrus.Info("Starting Scans\n\n")
	// microsoft bom generator
	go func() {
		sp := getSpinner(" Microsoft SBOM Generating", " Microsoft SBOM Finished")
		defer sp.Done()
		if err := pullDockerImageWithSpinner(MSBomURL, sp); err != nil {
			panic(err)
		}
		defer wg.Done()
		tmpDir, err := os.MkdirTemp(os.TempDir(), "fatbom")
		if err != nil {
			panic(tmpDir)
		}
		_, err = exec.Command(DockerCmd, "run", "-t",
			"-v", fullPathToDirToScan+":"+"/scan",
			"-v", tmpDir+":"+tmpDir,
			MSBomURL, "generate", "-b", "/scan",
			"-bc", "/scan", "-pn", "RootPkg",
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
		sp := getSpinner(" SPDX SBOM Generating", " SPDX SBOM Finished")
		defer sp.Done()
		if err := pullDockerImageWithSpinner(SpdxImageURL, sp); err != nil {
			panic(err)
		}
		defer wg.Done()
		tmpDir, err := os.MkdirTemp(os.TempDir(), "fatbom")
		if err != nil {
			panic(tmpDir)
		}
		_, err = exec.Command(
			DockerCmd, "run", "--rm", "-v", fullPathToDirToScan+":"+"/scan",
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
		sp := getSpinner(" K8-BOM Generating", " K8-BOM Finished")
		defer sp.Done()
		if err := pullDockerImageWithSpinner(K8BomImageURL, sp); err != nil {
			panic(err)
		}
		defer wg.Done()
		k8BomOut, err := exec.Command(DockerCmd, "run", "-v", fullPathToDirToScan+":"+"/scan", K8BomImageURL, "generate", "/scan", "--format", "json").Output()
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
		sp := getSpinner(" Syft Generating", " Syft Finished")
		defer sp.Done()
		if err := pullDockerImageWithSpinner(SyftImageURL, sp); err != nil {
			panic(err)
		}
		defer wg.Done()
		syftBomOut, err := exec.Command(
			DockerCmd, "run", "-v",
			fullPathToDirToScan+":"+"/scan", SyftImageURL,
			"packages",
			"dir:/scan", "-o", "spdx-json").CombinedOutput()
		if err != nil {
			panic(err)
		}
		syftRes := SpdxDocument{}
		json.Unmarshal(syftBomOut, &syftRes)
		scanResultsByTool[Syft.String()] = syftRes
	}()
	wg.Wait()
	cj.Stop()
	fmt.Println()

	data, err := json.MarshalIndent(scanResultsByTool, "\t", "\t")
	if err != nil {
		panic(err)
	}
	logrus.Info("Writing Semi Merged BOM to 'semi_merged_bom.json'")
	if err := os.WriteFile("semi_merged_bom.json", data, 0666); err != nil {
		panic(err)
	}
	logrus.Info("Wrote Semi Merged BOM to 'semi_merged_bom.json'")
	logrus.Info("Merging Scan Results")
	merged := Merge(scanResultsByTool)
	logrus.Info("Merged Scan Results")
	data, err = json.MarshalIndent(merged, "\t", "\t")
	if err != nil {
		panic(err)
	}
	logrus.Info("Writing Merged BOM to 'merged_bom.json'")
	if err := os.WriteFile("merged_bom.json", data, 0666); err != nil {
		panic(err)
	}
	logrus.Info("Wrote Merged BOM to 'merged_bom.json'")

}
