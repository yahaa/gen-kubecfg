package cert

// BundleCert 证书
type BundleCert struct {
	CSR        string `json:"csr" bson:"csr"`
	ClientCert string `json:"client_cert" bson:"client_cert"`
	ClientKey  string `json:"client_key" bson:"client_key"`
}
