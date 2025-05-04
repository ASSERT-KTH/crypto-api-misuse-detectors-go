## Missing Minimum TLS Version

argoproj-argo-workflows-26-1

https://github.com/argoproj/argo-workflows/commit/199016a6bed5284df3ec5caebbef9f2d018a2d43#diff-42623a9b98b20e51352de53c9e3283f5d13fcb2b9144bb2b62f7247119b773a1


> Gopher detects
```json
	{
		"FuncName": "crypto/tls.Config::InsecureSkipVerify",
		"Message": "Insecure Verification",
		"Slicing_Criteria": {
			"SourceCode": "InsecureSkipVerify: true,",
			"SourceFilename": "/analysis/repo/cmd/argo/commands/server.go",
			"SourceLineNum": 104,
			"ParentFunction": "NewServerCommand$1 (c *github.com/spf13/cobra.Command, args []string) error"
		},
		"Def_Use_Link": [
			{
				"SourceCode": "InsecureSkipVerify: true,",
				"SourceFilename": "/analysis/repo/cmd/argo/commands/server.go",
				"SourceLineNum": 104,
				"ParentFunction": "NewServerCommand$1 (c *github.com/spf13/cobra.Command, args []string) error"
			}
		],
		"Predicate_Type": "EQ_FALSE"
	},
```
> Is this what we are looking for? Why?
No. We note in the source code that InsecureSkipVerify is not security relvant here
```go
// InsecureSkipVerify will not impact the TLS listener. It is needed for the server to speak to itself for GRPC.
tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}, InsecureSkipVerify: true}
```

> What is the actual vulnerability?

Missing MIN_VERSION for TLS

```go
tlsMinVersion, err := env.GetInt("TLS_MIN_VERSION", tls.VersionTLS12)
```


> Is this a misuse?

Yes. In fact, Gopher detects outdated TLS suites, but not uncontrolled.




> How do we detect this?

- Perhaps `tls.CertificateRequestInfo`
- detect server run --> follow TLS definition --> check `tls.Config` has min version set

> What is the fix?
```go
tlsMinVersion, err := env.GetInt("TLS_MIN_VERSION", tls.VersionTLS12)
errors.CheckError(err)
tlsConfig = &tls.Config{
    Certificates:       []tls.Certificate{cer},
    InsecureSkipVerify: false, // InsecureSkipVerify will not impact the TLS listener. It is needed for the server to speak to itself for GRPC.
    MinVersion:         uint16(tlsMinVersion),
```