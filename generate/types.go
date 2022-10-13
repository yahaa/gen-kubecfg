package generate

import (
	"fmt"
	"strings"
)

const (
	TokenType      string = "token"
	ClientCertType string = "cert"

	ClusterScope   string = "cluster"
	NamespaceScope string = "namespace"
)

type Generator interface {
	ParseParams(p *Params)
	PreGenerate(p *Params)
	PostGenerate(p *Params)
	Generate(p *Params)
}

type Params struct {
	Type                    string
	ClusterEndpoint         string
	ClusterName             string
	ClusterCA               string
	ClientCert              string
	ClientKey               string
	Token                   string
	SaveAs                  string
	Username                string
	Scope                   string
	Namespaces              string
	ClusterRoles            []string
	ExistedSA               bool
	ServiceAccountNamespace string
}

func (p Params) NamespaceSlice() (res []string) {
	if p.Namespaces == "" {
		return
	}
	return strings.Split(p.Namespaces, ",")
}

func (p Params) SaveAsFile() string {
	filename := p.SaveAs
	if filename == "" {
		filename = fmt.Sprintf("%s.kubeconfig", p.Username)
	}
	return filename
}
