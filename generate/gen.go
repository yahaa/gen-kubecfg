package generate

import (
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	kubecmd "k8s.io/client-go/tools/clientcmd"
	kubecmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func GetClusterName(kubeConfig string) (string, error) {
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

func KubeConfig(input Params) {
	kubecfg := kubecmdapi.NewConfig()

	cluster := kubecmdapi.NewCluster()
	cluster.Server = input.ClusterEndpoint
	cluster.CertificateAuthorityData = []byte(input.ClusterCA)

	authInfo := kubecmdapi.NewAuthInfo()

	switch input.Type {
	case ClientCertType:
		authInfo.ClientCertificateData = []byte(input.ClientCert)
		authInfo.ClientKeyData = []byte(input.ClientKey)
	default:
		authInfo.Token = input.Token
	}

	kubeContext := kubecmdapi.NewContext()
	kubeContext.Cluster = input.ClusterName
	kubeContext.AuthInfo = input.Username

	kubecfg.Contexts[input.ClusterName] = kubeContext
	kubecfg.APIVersion = "v1"
	kubecfg.Kind = "Config"
	kubecfg.Clusters[input.ClusterName] = cluster
	kubecfg.AuthInfos[input.Username] = authInfo
	kubecfg.CurrentContext = input.ClusterName

	c, err := kubecmd.Write(*kubecfg)
	if err != nil {
		return
	}
	filename := input.SaveAsFile()

	if err := ioutil.WriteFile(filename, c, 0644); err != nil {
		log.Errorf("write kubeconfig file err: %v", err)
		return
	}

	log.Infof("generate kubeconfig for user '%s' success, save as ./%s", input.Username, filename)
}
