package collector

// TODO maybe identify the packages with crypto api usage

// // CryptoPackageDetector identifies repositories using cryptographic packages
// type CryptoPackageDetector struct {
// 	DefaultCryptoPkgs map[string]bool
// 	CryptoPatterns    []string
// }

// // NewCryptoPackageDetector creates a detector with default crypto package configurations
// func NewCryptoPackageDetector() *CryptoPackageDetector {
// 	return &CryptoPackageDetector{
// 		// Standard Go crypto packages
// 		DefaultCryptoPkgs: map[string]bool{
// 			"crypto":             true,
// 			"crypto/aes":         true,
// 			"crypto/cipher":      true,
// 			"crypto/des":         true,
// 			"crypto/dsa":         true,
// 			"crypto/ecdh":        true,
// 			"crypto/ecdsa":       true,
// 			"crypto/ed25519":     true,
// 			"crypto/elliptic":    true,
// 			"crypto/hmac":        true,
// 			"crypto/md5":         true,
// 			"crypto/rand":        true,
// 			"crypto/rc4":         true,
// 			"crypto/rsa":         true,
// 			"crypto/sha1":        true,
// 			"crypto/sha256":      true,
// 			"crypto/sha512":      true,
// 			"crypto/subtle":      true,
// 			"crypto/tls":         true,
// 			"crypto/x509":        true,
// 			"crypto/x509/pkcs12": true,
// 			"crypto/x509/pkcs7":  true,
// 		},

// 		// Additional patterns indicating cryptographic operations
// 		CryptoPatterns: []string{
// 			"Encrypt",
// 			"Decrypt",
// 			"Sign",
// 			"Verify",
// 			"GenerateKey",
// 			"ParsePEM",
// 			"ParsePrivateKey",
// 			"ParsePublicKey",
// 			"CreateCertificate",
// 			"HashFunc",
// 			"Cipher",
// 			"Block",
// 			"GCM",
// 			"NewCipher",
// 			"NewGCM",
// 			"NewMAC",
// 		},
// 	}
// }

// // DetectCryptoPkgUsage analyzes a repository for crypto package usage
// func (d *CryptoPackageDetector) DetectCryptoPkgUsage(repoPath string) ([]string, bool) {
// 	cryptoFiles := []string{}
// 	hasCryptoUsage := false

// 	// Walk through all Go files in the repository
// 	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}

// 		// Only process .go files
// 		if !info.IsDir() && strings.HasSuffix(path, ".go") {
// 			cryptoFile, detected := d.analyzeGoFile(path)
// 			if detected {
// 				cryptoFiles = append(cryptoFiles, cryptoFile)
// 				hasCryptoUsage = true
// 			}
// 		}

// 		return nil
// 	})

// 	if err != nil {
// 		log.Printf("Error walking repository: %v", err)
// 		return nil, false
// 	}

// 	return cryptoFiles, hasCryptoUsage
// }

// // analyzeGoFile checks a single Go file for crypto package usage
// func (d *CryptoPackageDetector) analyzeGoFile(filePath string) (string, bool) {
// 	fset := token.NewFileSet()

// 	// Parse the Go file
// 	file, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
// 	if err != nil {
// 		log.Printf("Error parsing file %s: %v", filePath, err)
// 		return "", false
// 	}

// 	// Check imports for crypto packages
// 	for _, imp := range file.Imports {
// 		importPath := strings.Trim(imp.Path.Value, "\"")
// 		if d.DefaultCryptoPkgs[importPath] {
// 			return filePath, true
// 		}
// 	}

// 	// Re-parse with full AST for deeper analysis
// 	file, err = parser.ParseFile(fset, filePath, nil, parser.ParseComments)
// 	if err != nil {
// 		log.Printf("Error parsing file %s: %v", filePath, err)
// 		return "", false
// 	}

// 	// Perform deeper AST analysis
// 	var cryptoDetected bool
// 	ast.Inspect(file, func(node ast.Node) bool {
// 		// Check for method/function names indicating crypto operations
// 		switch n := node.(type) {
// 		case *ast.CallExpr:
// 			if funcName := d.extractFuncName(n); funcName != "" {
// 				for _, pattern := range d.CryptoPatterns {
// 					if strings.Contains(strings.ToLower(funcName), strings.ToLower(pattern)) {
// 						cryptoDetected = true
// 						return false
// 					}
// 				}
// 			}
// 		}
// 		return true
// 	})

// 	return filePath, cryptoDetected
// }

// // extractFuncName gets the function name from a call expression
// func (d *CryptoPackageDetector) extractFuncName(call *ast.CallExpr) string {
// 	switch fn := call.Fun.(type) {
// 	case *ast.Ident:
// 		return fn.Name
// 	case *ast.SelectorExpr:
// 		return fn.Sel.Name
// 	default:
// 		return ""
// 	}
// }
