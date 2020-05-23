package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	cfsslcsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/yahaa/gen-kubecfg/utils"
	certv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubecmd "k8s.io/client-go/tools/clientcmd"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"
)

var (
	caConfigMap       = "extension-apiserver-authentication"
	kubeConfigVersion = "v1"
	kubeConfigKind    = "Config"
	caFileName        = "client-ca-file"

	commAns = struct {
		Username string
		SaveAs   string
		RoleType string `json:"roleType"`
	}{}

	clusterAns = struct {
		ClusterRoles []string
	}{}

	nsAns = struct {
		Namespaces   string
		ClusterRoles []string
	}{}

	kubeConfig string
	kclient    *kubernetes.Clientset
)

// CertBundle 证书
type CertBundle struct {
	CSR        string `json:"csr" bson:"csr"`
	ClientCert string `json:"client_cert" bson:"client_cert"`
	ClientKey  string `json:"client_key" bson:"client_key"`
}

func init() {
	flagSet := flag.CommandLine

	flagSet.StringVar(&kubeConfig, "kubeconfig", path.Join(os.Getenv("HOME"), "/.kube/config"), "kubeconfig name")

	flagSet.Parse(os.Args[1:])
}

func getClusterRoleNames() []string {
	clusterRoles, err := kclient.RbacV1().ClusterRoles().List(metav1.ListOptions{})
	if err != nil {
		log.Fatalf("list cluster role err: %v", err)
	}

	var clusterRoleNames []string

	for _, item := range clusterRoles.Items {
		clusterRoleNames = append(clusterRoleNames, item.Name)
	}
	return clusterRoleNames
}

func getClusterName(kubeConfig string) (string, error) {
	data, err := ioutil.ReadFile(kubeConfig)
	if err != nil {
		return "", err
	}

	cfg, err := kubecmd.Load(data)
	if err != nil {
		return "", err
	}

	if len(cfg.Clusters) == 0 {
		return "", fmt.Errorf("not found any cluster in this kubeconfig")
	}

	if cfg.CurrentContext == "" {
		for k := range cfg.Clusters {
			return k, nil
		}
	}

	return cfg.CurrentContext, nil
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

	clusterName, err := getClusterName(kubeConfig)
	if err != nil {
		log.Fatalf("get cluster name from kubeConfig err: %v", err)
	}

	clusterRoleNames := getClusterRoleNames()

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

	cm, err := kclient.CoreV1().ConfigMaps("kube-system").Get(caConfigMap, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("get config map %s err %w", caConfigMap, err)
	}

	ca, ok := cm.Data[caFileName]
	if !ok {
		log.Fatalf("not found %s", caFileName)
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

	cert := CertBundle{
		CSR:       string(csrBytes),
		ClientKey: string(keyBytes),
	}
	if err != nil {
		log.Fatalf("parse cfssl response err: %v", err)
	}

	if err := reCreateK8sCSR(commAns.Username, cert.CSR); err != nil {
		log.Fatalf("reCreate k8s csr err: %v", err)
	}

	if err := approvalK8sCSR(commAns.Username); err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	k8scsr, err := waitForK8sCsrReady(commAns.Username)
	if err != nil {
		log.Fatalf("approval k8s csr err: %v", err)
	}

	if len(k8scsr.Status.Certificate) == 0 {
		log.Fatalf("get root client cert err")
	}
	cert.ClientCert = string(k8scsr.Status.Certificate)

	generateKubeConfig(
		cfg.Host,
		clusterName,
		commAns.Username,
		ca,
		cert.ClientCert,
		cert.ClientKey,
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

	if err := generateBinding(commAns.Username, selectClusterRoleNames, inputNamespaces); err != nil {
		log.Errorf("generate binding err: %v", err)
		return
	}

	log.Info("success, enjoy it!")
}

func generateBinding(username string, clusterRoles []string, namespaces []string) error {
	if len(namespaces) == 0 {
		for _, cr := range clusterRoles {
			name := fmt.Sprintf("%s-%s", username, cr)
			if err := reCreateClusterRoleBinding(name, username, cr); err != nil {
				return fmt.Errorf("create cluster role binding for %s err: %w", username, err)
			}
			log.Infof("create cluster role binding %s success", name)
		}
	} else {
		for _, ns := range namespaces {
			if err := createNsIfNotExist(ns); err != nil {
				return fmt.Errorf("create namespace %s,err: %w", ns, err)
			}

			for _, cr := range clusterRoles {
				name := fmt.Sprintf("%s-%s", username, cr)
				if err := reCreateRoleBinding(name, username, ns, cr); err != nil {
					return fmt.Errorf("create role binding for %s err: %w", username, err)
				}
				log.Infof("create role binding %s in %s namespace success", name, ns)
			}
		}
	}
	return nil
}

func createNsIfNotExist(namespace string) error {
	_, err := kclient.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}

		if _, err := kclient.CoreV1().Namespaces().Create(ns); err != nil {
			return err
		}

	}

	return nil
}

func reCreateRoleBinding(name, username, namespace, roleRef string) error {
	_, err := kclient.RbacV1().RoleBindings(namespace).Get(name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if err == nil {
		if err := kclient.RbacV1().RoleBindings(namespace).Delete(name, &metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: rbacv1.UserKind,
				Name: username,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: roleRef,
		},
	}

	if _, err := kclient.RbacV1().RoleBindings(namespace).Create(rb); err != nil {
		return err
	}

	return nil
}
func reCreateClusterRoleBinding(name, username, roleRef string) error {
	_, err := kclient.RbacV1().ClusterRoleBindings().Get(name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if err == nil {
		if err := kclient.RbacV1().ClusterRoleBindings().Delete(name, &metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: rbacv1.UserKind,
				Name: username,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: roleRef,
		},
	}

	if _, err := kclient.RbacV1().ClusterRoleBindings().Create(crb); err != nil {
		return err
	}

	return nil
}

func reCreateK8sCSR(cn, csrStr string) error {
	k8sCSR := certv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: cn,
		},
		Spec: certv1beta1.CertificateSigningRequestSpec{
			Request: []byte(csrStr),
			Usages: []certv1beta1.KeyUsage{
				certv1beta1.UsageAny,
			},
		},
	}
	err := kclient.CertificatesV1beta1().CertificateSigningRequests().Delete(k8sCSR.Name, &metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if _, err := kclient.CertificatesV1beta1().CertificateSigningRequests().Create(&k8sCSR); err != nil {
		return err
	}

	return nil
}

func waitForK8sCsrReady(name string) (csr *certv1beta1.CertificateSigningRequest, err error) {
	for i := 0; i < 5; i++ {
		csr, err = kclient.CertificatesV1beta1().CertificateSigningRequests().Get(name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("get %s csr err: %v", err)
			time.Sleep(time.Second)
			continue
		}

		if len(csr.Status.Certificate) == 0 {
			time.Sleep(time.Second)
			continue
		}

		for _, c := range csr.Status.Conditions {
			if c.Type == certv1beta1.CertificateApproved {
				return
			}
		}
	}
	return nil, fmt.Errorf("wait csr to be approved timeout")
}

func approvalK8sCSR(name string) error {
	k8sCSR := &certv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: certv1beta1.CertificateSigningRequestStatus{
			Conditions: []certv1beta1.CertificateSigningRequestCondition{
				{Type: certv1beta1.CertificateApproved, LastUpdateTime: metav1.Now(), Message: "approval", Reason: "approval"},
			},
		},
	}

	if _, err := kclient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(k8sCSR); err != nil {
		return err
	}

	return nil
}

func generateKubeConfig(clusterEndpoint, clusterName, username, clusterCA, clientCert, clientKey, saveAs string) {
	kubecfg := kubeconfig.NewConfig()

	cluster := kubeconfig.NewCluster()
	cluster.Server = clusterEndpoint
	cluster.CertificateAuthorityData = []byte(clusterCA)

	authInfo := kubeconfig.NewAuthInfo()
	authInfo.ClientCertificateData = []byte(clientCert)
	authInfo.ClientKeyData = []byte(clientKey)

	kubeContext := kubeconfig.NewContext()
	kubeContext.Cluster = clusterName
	kubeContext.AuthInfo = username

	kubecfg.Contexts[clusterName] = kubeContext
	kubecfg.APIVersion = kubeConfigVersion
	kubecfg.Kind = kubeConfigKind
	kubecfg.Clusters[clusterName] = cluster
	kubecfg.AuthInfos[username] = authInfo
	kubecfg.CurrentContext = clusterName

	c, err := kubecmd.Write(*kubecfg)
	if err != nil {
		return
	}

	filename := saveAs

	if saveAs == "" {
		filename = fmt.Sprintf("%s.kubeconfig", username)
	}

	if err := ioutil.WriteFile(filename, c, 0644); err != nil {
		log.Errorf("write kubeconfig file err: %v", err)
		return
	}

	log.Infof("generate kubeconfig for user '%s' success, save as ./%s", username, filename)
}
