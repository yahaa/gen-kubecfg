package main

import (
	"flag"
	"os"
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	cfsslcsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/yahaa/gen-kubecfg/cert"
	"github.com/yahaa/gen-kubecfg/kubecfg"
	"github.com/yahaa/gen-kubecfg/utils"
)

var (
	caConfigMap = "extension-apiserver-authentication"
	caFileName  = "client-ca-file"
	kubeConfig  string
	kclient     *kubernetes.Clientset
	token       string
)

func init() {
	flagSet := flag.CommandLine

	flagSet.StringVar(&kubeConfig, "kubeconfig", path.Join(os.Getenv("HOME"), "/.kube/config"), "kubeconfig name")

	flagSet.Parse(os.Args[1:])
}

func main() {
	cfg, err := utils.NewClusterConfig(kubeConfig)
	if err != nil {
		log.Fatalf("create cluster config err: %v", err)
	}
	kclient, err = utils.NewClientset(kubeConfig)
	if err != nil {
		log.Fatalf("create k8s client err: %v", err)
	}

	clusterName, err := kubecfg.GetClusterName(kubeConfig)
	if err != nil {
		log.Fatalf("get cluster name from kubeConfig err: %v", err)
	}

	cm, err := kclient.CoreV1().ConfigMaps("kube-system").Get(caConfigMap, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("get config map %s err %w", caConfigMap, err)
	}
	ca, ok := cm.Data[caFileName]
	if !ok {
		log.Fatalf("not found %s", caFileName)
	}

	kt := utils.NewKubeTool(kclient)

	var cfgTypeQ = []*survey.Question{
		{
			Name: "cfgType",
			Prompt: &survey.Select{
				Message: "Please choose a access type of kubeconfig:",
				Options: []string{"token", "ssl"},
				Default: "token",
			},
		},
	}

	var cfgTypeAns = struct {
		CfgType string
	}{}

	if err := survey.Ask(cfgTypeQ, &cfgTypeAns); err != nil {
		log.Fatalf("got questions answers err: %v", err)
	}

	if cfgTypeAns.CfgType == "token" {
		generateTokenKubeConfig(kt, cfg, clusterName, ca)
	} else {
		generateSSLKubeConfig(kt, cfg, clusterName, ca)
	}
	log.Info("success, enjoy it!")
}

func generateSSLKubeConfig(kt *utils.KubeTool, cfg *rest.Config, clusterName, ca string) {
	clusterRoleNames := kt.GetClusterRoleNames()

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
			Name: "roleType",
			Prompt: &survey.Select{
				Message: "Please choose permission type for this user:",
				Options: []string{"cluster", "namespace"},
				Default: "cluster",
			},
		},
	}

	var clusterQ = []*survey.Question{
		{
			Name: "clusterRoles",
			Prompt: &survey.MultiSelect{
				Message: "Please choose some cluster roles:",
				Options: clusterRoleNames,
			},
		},
	}

	var namespaceQ = []*survey.Question{
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

	var commAns = struct {
		Username string
		SaveAs   string
		RoleType string `json:"roleType"`
	}{}

	var clusterAns = struct {
		ClusterRoles []string
	}{}

	var nsAns = struct {
		Namespaces   string
		ClusterRoles []string
	}{}

	if err := survey.Ask(commonQ, &commAns); err != nil {
		log.Fatalf("got questions answers err: %v", err)
	}

	if commAns.RoleType == "cluster" {
		if err := survey.Ask(clusterQ, &clusterAns); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	} else {
		if err := survey.Ask(namespaceQ, &nsAns); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
	}

	csr := cfsslcsr.CertificateRequest{
		CN: commAns.Username,
		KeyRequest: &cfsslcsr.KeyRequest{
			A: "ecdsa",
			S: 256,
		},
	}

	csrBytes, keyBytes, err := cfsslcsr.ParseRequest(&csr)
	if err != nil {
		log.Fatalf("parse csr request err: %v", err)
	}

	bundleCert := cert.BundleCert{
		CSR:       string(csrBytes),
		ClientKey: string(keyBytes),
	}

	if err := kt.ReCreateK8sCSR(commAns.Username, bundleCert.CSR); err != nil {
		log.Fatalf("reCreate k8s csr err: %v", err)
	}

	if err := kt.ApprovalK8sCSR(commAns.Username); err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	k8sCSR, err := kt.WaitForK8sCsrReady(commAns.Username)
	if err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	if len(k8sCSR.Status.Certificate) == 0 {
		log.Fatalf("get root client bundleCert err")
	}
	bundleCert.ClientCert = string(k8sCSR.Status.Certificate)

	kubecfg.GenerateKubeConfig(
		kubecfg.SSLType,
		cfg.Host,
		clusterName,
		commAns.Username,
		ca,
		bundleCert.ClientCert,
		bundleCert.ClientKey,
		"",
		commAns.SaveAs,
	)

	var selectClusterRoleNames []string
	var inputNamespaces []string

	if commAns.RoleType == "cluster" {
		selectClusterRoleNames = clusterAns.ClusterRoles
	} else {
		selectClusterRoleNames = nsAns.ClusterRoles
	}

	if nsAns.Namespaces != "" {
		inputNamespaces = strings.Split(nsAns.Namespaces, ",")
	}

	if err := kt.GenerateBinding("User", "", commAns.Username, selectClusterRoleNames, inputNamespaces); err != nil {
		log.Errorf("generate binding err: %v", err)
		return
	}
}

func generateTokenKubeConfig(kt *utils.KubeTool, cfg *rest.Config, clusterName, ca string) {
	clusterRoleNames := kt.GetClusterRoleNames()

	var commonQ = []*survey.Question{
		{
			Name:     "username",
			Prompt:   &survey.Input{Message: "Please input username which you want to generate kubeconfig for:"},
			Validate: survey.Required,
		},
		{
			Name: "saveAs",
			Prompt: &survey.Input{
				Message: "Please input kubeconfig save as name(default 'username.kubeconfig'):",
			},
		},
		{
			Name: "accountType",
			Prompt: &survey.Select{
				Message: "Please choose using existed service account or create a new one:",
				Options: []string{"existed", "new"},
				Default: "existed",
			},
		},
		{
			Name:     "nameSpace",
			Prompt:   &survey.Input{Message: "Please input namespace of the generated service account:"},
			Validate: survey.Required,
		},
	}

	var newAccountNameQ = []*survey.Question{
		{
			Name:     "accountName",
			Prompt:   &survey.Input{Message: "Please input service account name which you want to generate kubeconfig for:"},
			Validate: survey.Required,
		},
	}

	var roleTypeQ = []*survey.Question{
		{
			Name: "roleType",
			Prompt: &survey.Select{
				Message: "Please choose permission type for this user:",
				Options: []string{"cluster", "namespace"},
				Default: "cluster",
			},
		},
	}

	var clusterQ = []*survey.Question{
		{
			Name: "clusterRoles",
			Prompt: &survey.MultiSelect{
				Message: "Please choose some cluster roles:",
				Options: clusterRoleNames,
			},
		},
	}

	var namespaceQ = []*survey.Question{
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

	var commAns = struct {
		Username    string
		SaveAs      string
		AccountType string
		NameSpace   string
	}{}

	var accountNameAns = struct {
		AccountName string
	}{}

	var roleTypeAns = struct {
		RoleType string
	}{}

	var clusterAns = struct {
		ClusterRoles []string
	}{}

	var nsAns = struct {
		Namespaces   string
		ClusterRoles []string
	}{}

	if err := survey.Ask(commonQ, &commAns); err != nil {
		log.Fatalf("got questions answers err: %v", err)
	}

	if commAns.AccountType == "new" {
		if err := survey.Ask(newAccountNameQ, &accountNameAns); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
		accountNames := kt.GetServiceAccountNames(commAns.NameSpace)
		for _, names := range accountNames {
			if names == accountNameAns.AccountName {
				log.Fatalf("service account \"%s\" already exist !", names)
			}
		}
		if err := survey.Ask(roleTypeQ, &roleTypeAns); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: accountNameAns.AccountName,
			},
		}
		sa, err := kclient.CoreV1().ServiceAccounts(commAns.NameSpace).Create(sa)
		if err != nil {
			log.Fatalf("service account create err: %v", err)
		}

		if roleTypeAns.RoleType == "cluster" {
			if err := survey.Ask(clusterQ, &clusterAns); err != nil {
				log.Fatalf("got questions answers err: %v", err)
			}
		} else {
			if err := survey.Ask(namespaceQ, &nsAns); err != nil {
				log.Fatalf("got questions answers err: %v", err)
			}
		}
		var selectClusterRoleNames []string
		var inputNamespaces []string

		if roleTypeAns.RoleType == "cluster" {
			selectClusterRoleNames = clusterAns.ClusterRoles
		} else {
			selectClusterRoleNames = nsAns.ClusterRoles
		}

		if nsAns.Namespaces != "" {
			inputNamespaces = strings.Split(nsAns.Namespaces, ",")
		}

		if err := kt.GenerateBinding("ServiceAccount", commAns.NameSpace, commAns.Username, selectClusterRoleNames, inputNamespaces); err != nil {
			log.Errorf("generate binding err: %v", err)
			return
		}
		sa, err = kclient.CoreV1().ServiceAccounts(commAns.NameSpace).Get(accountNameAns.AccountName, metav1.GetOptions{})
		if err != nil {
			log.Fatalf("got service account err: %v", err)
		}
		secret, err := kclient.CoreV1().Secrets(commAns.NameSpace).Get(sa.Secrets[0].Name, metav1.GetOptions{})
		if err != nil {
			log.Fatalf("got service account err: %v", err)
		}
		token = string(secret.Data["token"])

	} else {
		accountNames := kt.GetServiceAccountNames(commAns.NameSpace)
		var accountNameQ = []*survey.Question{
			{
				Name: "accountName",
				Prompt: &survey.Select{
					Message: "Please choose one service account:",
					Options: accountNames,
				},
			},
		}
		if err := survey.Ask(accountNameQ, &accountNameAns); err != nil {
			log.Fatalf("got questions answers err: %v", err)
		}
		sa, err := kclient.CoreV1().ServiceAccounts(commAns.NameSpace).Get(accountNameAns.AccountName, metav1.GetOptions{})
		if err != nil {
			log.Fatalf("got service account err: %v", err)
		}
		secret, err := kclient.CoreV1().Secrets(commAns.NameSpace).Get(sa.Secrets[0].Name, metav1.GetOptions{})
		if err != nil {
			log.Fatalf("got service account err: %v", err)
		}
		token = string(secret.Data["token"])
	}

	kubecfg.GenerateKubeConfig(
		kubecfg.TokenType,
		cfg.Host,
		clusterName,
		commAns.Username,
		ca,
		"",
		"",
		token,
		commAns.SaveAs,
	)
}
