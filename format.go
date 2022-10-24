package main

//  TODO: parametrize Rootpackage rather than hardcoding it.

var SpdxTemplate string = `
SPDXVersion: {{.Version}}
DataLicense: {{.DataLicense}}
SPDXID: {{.ID}}
DocumentName: {{.Name}}
DocumentNamespace: {{.Namespace}}
{{range .CreationInfo.Creators -}}
{{$creator := . -}}
Creator: {{$creator}}
{{end -}}

{{range .Files -}}
{{$file := . -}}

Relationship: SPDXRef-Package-RootPackage CONTAINS {{$file.ID}}

FileName: {{$file.Name}}
SPDXID: {{$file.ID}}
{{ range $file.Checksums -}}
FileChecksum: {{.Algorithm}}: {{.Value}}
{{end -}}
{{ range $file.FileTypes -}}
FileType: {{.}}
{{end -}}
LicenseConcluded: {{$file.LicenseConcluded}}
{{range $file.LicenseInfoInFile -}}
LicenseInfoInFile: {{.}}
{{end -}}
FileCopyrightText: {{$file.CopyrightText}}

{{end -}}

{{range $i, $package := .Packages -}}
{{- if eq 0 $i}}
Relationship: SPDXRef-Package-RootPackage DEPENDS_ON {{$package.ID}}
{{- end}}
##### Package: {{$package.Name}}

PackageName: {{$package.Name}}
SPDXID: {{$package.ID}}
PackageDownloadLocation: {{$package.DownloadLocation}}
FilesAnalyzed: {{$package.FilesAnalyzed}}
PackageLicenseConcluded: {{$package.LicenseConcluded}}
PackageVersion: {{$package.Version}}
{{range $package.ExternalRefs -}}
ExternalRef: {{.Category}} {{.Type}} {{.Locator}}
{{end -}}
PackageLicenseDeclared: {{$package.LicenseDeclared}}
{{- if eq $package.CopyrightText "NOASSERTION"}}
PackageCopyrightText: {{$package.CopyrightText}}
{{- else }}
PackageCopyrightText: <text> 
 {{$package.CopyrightText}}
</text>
{{- end}}


{{end -}}

`
