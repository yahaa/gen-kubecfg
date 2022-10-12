package generate

import (
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	kubecmd "k8s.io/client-go/tools/clientcmd"
	kubecmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	TokenType KubeConfigType = "token"
	SSLType   KubeConfigType = "ssl"
)

type KubeConfigType string

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

func KubeConfig(cfgType KubeConfigType, clusterEndpoint, clusterName, username, clusterCA, clientCert, clientKey, token, saveAs string) {
	kubecfg := kubecmdapi.NewConfig()

	cluster := kubecmdapi.NewCluster()
	cluster.Server = clusterEndpoint
	cluster.CertificateAuthorityData = []byte(clusterCA)

	authInfo := kubecmdapi.NewAuthInfo()

	if cfgType == SSLType {
		authInfo.ClientCertificateData = []byte(clientCert)
		authInfo.ClientKeyData = []byte(clientKey)
	} else {
		authInfo.Token = token
	}

	kubeContext := kubecmdapi.NewContext()
	kubeContext.Cluster = clusterName
	kubeContext.AuthInfo = username

	kubecfg.Contexts[clusterName] = kubeContext
	kubecfg.APIVersion = "v1"
	kubecfg.Kind = "Config"
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
