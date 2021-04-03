package utils

import (
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/log"
	certv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubeTool struct {
	client kubernetes.Interface
}

func NewKubeTool(client kubernetes.Interface) *KubeTool {
	return &KubeTool{client: client}
}

func (kt *KubeTool) createNsIfNotExist(namespace string) error {
	_, err := kt.client.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}

		if _, err := kt.client.CoreV1().Namespaces().Create(ns); err != nil {
			return err
		}

	}

	return nil
}

func (kt *KubeTool) reCreateRoleBinding(roleBindingType, name, username, namespace, roleRef, saNameSpace string) error {
	_, err := kt.client.RbacV1().RoleBindings(namespace).Get(name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if err == nil {
		if err := kt.client.RbacV1().RoleBindings(namespace).Delete(name, &metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	var subj []rbacv1.Subject
	if roleBindingType == "User" {
		subj = []rbacv1.Subject{
			{
				Kind: rbacv1.UserKind,
				Name: username,
			},
		}
	} else {
		subj = []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      username,
				Namespace: saNameSpace,
			},
		}
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subjects: subj,
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: roleRef,
		},
	}

	if _, err := kt.client.RbacV1().RoleBindings(namespace).Create(rb); err != nil {
		return err
	}

	return nil
}

func (kt *KubeTool) reCreateClusterRoleBinding(roleBindingType, name, username, roleRef, saNameSpace string) error {
	_, err := kt.client.RbacV1().ClusterRoleBindings().Get(name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if err == nil {
		if err := kt.client.RbacV1().ClusterRoleBindings().Delete(name, &metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	var subj []rbacv1.Subject
	if roleBindingType == "User" {
		subj = []rbacv1.Subject{
			{
				Kind: rbacv1.UserKind,
				Name: username,
			},
		}
	} else {
		subj = []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      username,
				Namespace: saNameSpace,
			},
		}
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Subjects: subj,
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: roleRef,
		},
	}

	if _, err := kt.client.RbacV1().ClusterRoleBindings().Create(crb); err != nil {
		return err
	}

	return nil
}

func (kt *KubeTool) ReCreateK8sCSR(cn, csrStr string) error {
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
	err := kt.client.CertificatesV1beta1().CertificateSigningRequests().Delete(k8sCSR.Name, &metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if _, err := kt.client.CertificatesV1beta1().CertificateSigningRequests().Create(&k8sCSR); err != nil {
		return err
	}

	return nil
}

func (kt *KubeTool) WaitForK8sCsrReady(name string) (csr *certv1beta1.CertificateSigningRequest, err error) {
	for i := 0; i < 5; i++ {
		csr, err = kt.client.CertificatesV1beta1().CertificateSigningRequests().Get(name, metav1.GetOptions{})
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

func (kt *KubeTool) ApprovalK8sCSR(name string) error {
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

	if _, err := kt.client.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(k8sCSR); err != nil {
		return err
	}

	return nil
}

func (kt *KubeTool) GetServiceAccountNames(nameSpace string) []string {
	serviceAccounts, err := kt.client.CoreV1().ServiceAccounts(nameSpace).List(metav1.ListOptions{})
	if err != nil {
		log.Fatalf("list cluster role err: %v", err)
	}
	var accountNames []string
	for _, item := range serviceAccounts.Items {
		accountNames = append(accountNames, item.Name)
	}
	return accountNames
}

func (kt *KubeTool) GetClusterRoleNames() []string {
	clusterRoles, err := kt.client.RbacV1().ClusterRoles().List(metav1.ListOptions{})
	if err != nil {
		return nil
	}

	var clusterRoleNames []string

	for _, item := range clusterRoles.Items {
		clusterRoleNames = append(clusterRoleNames, item.Name)
	}
	return clusterRoleNames
}

func (kt *KubeTool) GenerateBinding(roleBindingType, saNameSpace, username string, clusterRoles []string, namespaces []string) error {
	if len(namespaces) == 0 {
		for _, cr := range clusterRoles {
			name := fmt.Sprintf("%s-%s", username, cr)
			if err := kt.reCreateClusterRoleBinding(roleBindingType, name, username, cr, saNameSpace); err != nil {
				return fmt.Errorf("create cluster role binding for %s err: %w", username, err)
			}
			log.Infof("create cluster role binding %s success", name)
		}
	} else {
		for _, ns := range namespaces {
			if err := kt.createNsIfNotExist(ns); err != nil {
				return fmt.Errorf("create namespace %s,err: %w", ns, err)
			}

			for _, cr := range clusterRoles {
				name := fmt.Sprintf("%s-%s", username, cr)
				if err := kt.reCreateRoleBinding(roleBindingType, name, username, ns, cr, saNameSpace); err != nil {
					return fmt.Errorf("create role binding for %s err: %w", username, err)
				}
				log.Infof("create role binding %s in %s namespace success", name, ns)
			}
		}
	}
	return nil
}
