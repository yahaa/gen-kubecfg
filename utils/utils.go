package utils

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeConfigEnv (optionally) specify the location of kubeconfig file
const KubeConfigEnv = "KUBECONFIG"

func NewClusterConfig(kubeconfig string) (*rest.Config, error) {
	var (
		cfg *rest.Config
		err error
	)

	if kubeconfig == "" {
		kubeconfig = os.Getenv(KubeConfigEnv)
	}

	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("Error creating config from specified file: %s %v\n", kubeconfig, err)
		}
	} else {
		if cfg, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	}

	cfg.QPS = 100
	cfg.Burst = 100

	return cfg, nil
}

func NewClientset(kubeconfig string) (*kubernetes.Clientset, error) {
	cfg, err := NewClusterConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(cfg)
}
