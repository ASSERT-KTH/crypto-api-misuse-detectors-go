
## Insufficient entropy in Oauth

https://github.com/argoproj/argo-cd/commit/17f7f4f462bdb233e1b9b36f67099f41052d8cb0


> Gopher detects

```json

	{
		"FuncName": "crypto/rsa.GenerateKey",
		"Message": "RSA-512 and RSA-1024 is insecure, RSA-2048 is Acceptable but not recommended.\nWe Found: 2048",
		"Slicing_Criteria": {
			"SourceCode": "generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)",
			"SourceFilename": "/analysis/repo/server/auth/sso/sso.go",
			"SourceLineNum": 136,
			"ParentFunction": "newSso (factory github.com/argoproj/argo-workflows/v3/server/auth/sso.providerFactory, c github.com/argoproj/argo-workflows/v3/server/auth/sso.Config, secretsIf k8s.io/client-go/kubernetes/typed/core/v1.SecretInterface, baseHRef string, secure bool) (github.com/argoproj/argo-workflows/v3/server/auth/sso.Interface, error)"
		},
		"Def_Use_Link": [
			{
				"SourceCode": "generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)",
				"SourceFilename": "/analysis/repo/server/auth/sso/sso.go",
				"SourceLineNum": 136,
				"ParentFunction": "newSso (factory github.com/argoproj/argo-workflows/v3/server/auth/sso.providerFactory, c github.com/argoproj/argo-workflows/v3/server/auth/sso.Config, secretsIf k8s.io/client-go/kubernetes/typed/core/v1.SecretInterface, baseHRef string, secure bool) (github.com/argoproj/argo-workflows/v3/server/auth/sso.Interface, error)"
			}
		],
		"Predicate_Type": "GEQ"
	},

```

> Is this what we are looking for? Why?

No. Looking at the changes and discussion, the issue seems to be insufficient entropy in `stateNonce`.

> What is the actual vulnerability?

Oauth2: attackers guessing tokens (e.g. authtokens)

The probability of an attacker guessing generated tokens (and other
credentials not intended for handling by end-users) MUST be less than
or equal to 2^(-128) and SHOULD be less than or equal to 2^(-160).

```go
stateNonce := rand.RandString(10)
// ... 
url = oauth2conf.AuthCodeURL(stateNonce, opts...)
```
> What is the fix?

```go
// According to the spec (https://www.rfc-editor.org/rfc/rfc6749#section-10.10), this must be guessable with
// probability <= 2^(-128). The following call generates one of 52^24 random strings, ~= 2^136 possibilities.
stateNonce, err := rand.String(24)
errors.CheckError(err)
```

> Is this a misuse?


> How do we detect this?



