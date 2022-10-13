package main

import (
	"flag"
	"os"
	"path"

	"github.com/AlecAivazis/survey/v2"
	"github.com/cloudflare/cfssl/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/yahaa/gen-kubecfg/generate"
	"github.com/yahaa/gen-kubecfg/generate/cert"
	"github.com/yahaa/gen-kubecfg/generate/token"
	"github.com/yahaa/gen-kubecfg/utils"
)

var (
	caConfigMap = "extension-apiserver-authentication"
	caFileName  = "client-ca-file"
	kubeConfig  string
	clientSet   *kubernetes.Clientset
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
	clientSet, err = utils.NewClientset(kubeConfig)
	if err != nil {
		log.Fatalf("create k8s client err: %v", err)
	}

	clusterName, err := generate.GetClusterName(kubeConfig)
	if err != nil {
		log.Fatalf("get cluster name from kubeConfig err: %v", err)
	}

	cm, err := clientSet.CoreV1().ConfigMaps("kube-system").Get(caConfigMap, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("get config map %s err %w", caConfigMap, err)
	}

	ca, ok := cm.Data[caFileName]
	if !ok {
		log.Fatalf("not found %s", caFileName)
	}

	client := generate.NewClient(clientSet)

	params := generate.Params{
		ClusterEndpoint: cfg.Host,
		ClusterName:     clusterName,
		ClusterCA:       ca,
	}

	var typeQ = []*survey.Question{
		{
			Name: "type",
			Prompt: &survey.Select{
				Message: "Please choose an access type of kubeconfig:",
				Options: []string{generate.TokenType, generate.ClientCertType},
				Default: generate.TokenType,
			},
		},
	}

	if err := survey.Ask(typeQ, &params); err != nil {
		log.Fatalf("got questions answers err: %v", err)
	}

	var g generate.Generator
	switch params.Type {
	case generate.ClientCertType:
		g = cert.New(*client)
	case generate.TokenType:
		g = token.New(*client)
	default:
		log.Fatalf("not support type: %v", params.Type)
	}

	g.ParseParams(&params)
	g.PreGenerate(&params)
	g.Generate(&params)
	g.PostGenerate(&params)
}
