package cert

import (
	"github.com/AlecAivazis/survey/v2"
	cfssl "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/yahaa/gen-kubecfg/generate"
)

// BundleCert 证书
type BundleCert struct {
	CSR        string `json:"csr" bson:"csr"`
	ClientCert string `json:"client_cert" bson:"client_cert"`
	ClientKey  string `json:"client_key" bson:"client_key"`
}

type certKubeconfig struct {
	client generate.Client
}

func New(c generate.Client) generate.Generator {
	return &certKubeconfig{
		client: c,
	}
}

func (g *certKubeconfig) Generate(p *generate.Params) {
	generate.KubeConfig(*p)
}

func (g *certKubeconfig) ParseParams(p *generate.Params) {
	clusterRoleNames := g.client.GetClusterRoleNames()

	var commonQ = []*survey.Question{
		{
			Name:     "username",
			Prompt:   &survey.Input{Message: "Please input username which you want to generate kubeconfig for:"},
			Validate: survey.Required,
		},
		{
			Name: "saveAs",
			Prompt: &survey.Input{
				Message: "Please input kubeconfig save as name(default 'username.kubeconfig):",
			},
		},
		{
			Name: "scope",
			Prompt: &survey.Select{
				Message: "Please choose permission scope for this user:",
				Options: []string{generate.ClusterScope, generate.NamespaceScope},
				Default: generate.ClusterScope,
			},
		},
	}
	if err := survey.Ask(commonQ, p); err != nil {
		log.Fatalf("got questions answers err: %v", err)
	}

	if p.Scope == generate.ClusterScope {
		var scopeQ = []*survey.Question{
			{
				Name: "clusterRoles",
				Prompt: &survey.MultiSelect{
					Message: "Please choose some cluster roles:",
					Options: clusterRoleNames,
				},
			},
		}
		if err := survey.Ask(scopeQ, p); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	} else {
		var scopeQ = []*survey.Question{
			{
				Name: "namespaces",
				Prompt: &survey.Input{
					Message: "Please input namespaces you want to generate kubeconfig for, split by ',':",
				},
				Validate: survey.Required,
			},
			{
				Name: "clusterRoles",
				Prompt: &survey.MultiSelect{
					Message: "Please choose some cluster roles:",
					Options: clusterRoleNames,
				},
			},
		}
		if err := survey.Ask(scopeQ, p); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	}
}

func (g *certKubeconfig) PreGenerate(p *generate.Params) {
	csr := cfssl.CertificateRequest{
		CN: p.Username,
		KeyRequest: &cfssl.KeyRequest{
			A: "ecdsa",
			S: 256,
		},
	}

	csrBytes, keyBytes, err := cfssl.ParseRequest(&csr)
	if err != nil {
		log.Fatalf("parse csr request err: %v", err)
	}

	bundleCert := BundleCert{
		CSR:       string(csrBytes),
		ClientKey: string(keyBytes),
	}

	if err := g.client.ReCreateK8sCSR(p.Username, bundleCert.CSR); err != nil {
		log.Fatalf("reCreate k8s csr err: %v", err)
	}

	if err := g.client.ApprovalK8sCSR(p.Username); err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	k8sCSR, err := g.client.WaitForK8sCsrReady(p.Username)
	if err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	if len(k8sCSR.Status.Certificate) == 0 {
		log.Fatalf("get root client bundleCert err")
	}

	bundleCert.ClientCert = string(k8sCSR.Status.Certificate)

	p.ClientCert = bundleCert.ClientCert
	p.ClientKey = bundleCert.ClientKey

}
func (g *certKubeconfig) PostGenerate(p *generate.Params) {
	if err := g.client.GenerateBinding("User", "", p.Username, p.ClusterRoles, p.NamespaceSlice()); err != nil {
		log.Errorf("generate binding err: %v", err)
	}
}
