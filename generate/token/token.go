package token

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/cloudflare/cfssl/log"
	"github.com/yahaa/gen-kubecfg/generate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type tokenKubeconfig struct {
	client    generate.Client
	clientSet kubernetes.Interface
}

func New(c generate.Client) generate.Generator {
	return &tokenKubeconfig{
		client:    c,
		clientSet: c.ClientSet(),
	}
}

func (g *tokenKubeconfig) Generate(p *generate.Params) {
	generate.KubeConfig(*p)
}

func (g *tokenKubeconfig) ParseParams(p *generate.Params) {
	clusterRoleNames := g.client.GetClusterRoleNames()

	var commonQ = []*survey.Question{
		{
			Name: "existedSA",
			Prompt: &survey.Confirm{
				Message: "Please confirm using existed service account('y' using existed, 'n' create a new one):",
				Default: false,
			},
		},
		{
			Name:     "serviceAccountNamespace",
			Prompt:   &survey.Input{Message: "Please input namespace of the service account:"},
			Validate: survey.Required,
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

	if !p.ExistedSA {
		var inputSAQ = []*survey.Question{
			{
				Name:     "username",
				Prompt:   &survey.Input{Message: "Please input service account name which you want to generate kubeconfig for:"},
				Validate: survey.Required,
			},
		}
		if err := survey.Ask(inputSAQ, p); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	} else {
		accountNames := g.client.GetServiceAccountNames(p.ServiceAccountNamespace)
		var selectSAQ = []*survey.Question{
			{
				Name: "username",
				Prompt: &survey.Select{
					Message: "Please choose one service account:",
					Options: accountNames,
				},
			},
		}
		if err := survey.Ask(selectSAQ, p); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	}

	var saveAsQ = []*survey.Question{
		{
			Name: "saveAs",
			Prompt: &survey.Input{
				Message: "Please input kubeconfig save as name(default 'username.kubeconfig'):",
			},
		},
	}
	if err := survey.Ask(saveAsQ, p); err != nil {
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

func (g *tokenKubeconfig) PreGenerate(p *generate.Params) {
	if !p.ExistedSA {
		accountNames := g.client.GetServiceAccountNames(p.ServiceAccountNamespace)
		for _, name := range accountNames {
			if name == p.Username {
				log.Fatalf("service account \"%s\" already exist !", name)
			}
		}
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Username,
			},
		}

		if _, err := g.clientSet.CoreV1().ServiceAccounts(p.ServiceAccountNamespace).Create(sa); err != nil {
			log.Fatalf("service account create err: %v", err)
		}
	}

	sa, err := g.clientSet.CoreV1().ServiceAccounts(p.ServiceAccountNamespace).Get(p.Username, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("got service account err: %v", err)
	}

	secret, err := g.clientSet.CoreV1().Secrets(p.ServiceAccountNamespace).Get(sa.Secrets[0].Name, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("got service account err: %v", err)
	}

	p.Token = string(secret.Data["token"])
}
func (g *tokenKubeconfig) PostGenerate(p *generate.Params) {
	if err := g.client.GenerateBinding("ServiceAccount", p.ServiceAccountNamespace, p.Username, p.ClusterRoles, p.NamespaceSlice()); err != nil {
		log.Errorf("generate binding err: %v", err)
	}
}
