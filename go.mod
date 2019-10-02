module github.com/kayrus/ingress-terraform

go 1.13

require (
	github.com/gophercloud/utils v0.0.0-20190829151529-94e6842399e5 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/prometheus/client_golang v1.1.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	gopkg.in/gcfg.v1 v1.2.3 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v0.0.0
	k8s.io/cloud-provider v0.0.0 // indirect
	k8s.io/cloud-provider-openstack v1.16.0
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20190923111123-69764acb6e8e // indirect
)

replace (
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20190913145653-2bd9643cee5b
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20190913145653-2bd9643cee5b
	k8s.io/client-go => k8s.io/kubernetes/staging/src/k8s.io/client-go v0.0.0-20190913145653-2bd9643cee5b
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20190913145653-2bd9643cee5b
)
