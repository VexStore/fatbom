package main

import (
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"
)

const (
	SyftImageURL  string = "docker.io/anchore/syft"
	K8BomImageURL string = "k8s.gcr.io/bom/bom:v0.3.0"
	MSBomURL      string = "ghcr.io/sbs2001/ms_sbom:v0.0.1"
)

func main() {
	dirToScan := flag.String("s", "./", "directory to scan")
	flag.Parse()
	fullPath, err := filepath.Abs(*dirToScan)
	if err != nil {
		panic(err)
	}

	// z := []string{"docker", "run", "-v", K8BomImageURL, fullPath + ":" + "/scan", "generate", "/scan"}
	// fmt.Println(strings.Join(z, " "))
	out, err := exec.Command("docker", "run", "-v", fullPath+":"+"/scan", K8BomImageURL, "generate", "/scan").CombinedOutput()
	if err != nil {
		panic(err)
	}
	fmt.Print(string(out))
}
