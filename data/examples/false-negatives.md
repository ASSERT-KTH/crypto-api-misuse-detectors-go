
### weaveworks-weave-gitops-870-4


Why?

Maybe they use non-standard way of using http "httptest"

### dexidp-dex-204-1
https://github.com/dexidp/dex/commit/324b1c886b407594196113a3dbddebe38eecd4e8
>Is a misuse?

Not really. Kind of an injection issue. Santization.

```json
{
  "id": 204,
  "package": "github.com/dexidp/dex/connector/saml",
  "go_version": "1.15",
  "vul_name": "Signature Validation Bypass",
  "references": [
    "https://github.com/dexidp/dex/security/advisories/GHSA-m9hp-7r99-94h5",
    "https://github.com/dexidp/dex/commit/324b1c886b407594196113a3dbddebe38eecd4e8"
  ],
  "publish": "Introduced: 29 Dec 2020",
  "cwe": "CWE-347",
  "cve": "CVE-2020-26290",
  "summary": "Affected versions of this package are vulnerable to Signature Validation Bypass. Disclosures of a few vulnerabilities impact users leveraging the SAML connector.",
  "level": "critical",
  "score": "9.1",
  "remediation_description": "Upgrade github.com/dexidp/dex/connector/saml to version 2.27.0 or higher.",
  "vul_range": "\u003e=2.1.0 \u003c2.27.0",
}
```