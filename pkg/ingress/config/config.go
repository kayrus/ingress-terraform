/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	openstack_provider "k8s.io/cloud-provider-openstack/pkg/cloudprovider/providers/openstack"
)

// Config struct contains ingress controller configuration
type Config struct {
	ClusterName string                      `mapstructure:"cluster-name"`
	Kubernetes  kubeConfig                  `mapstructure:"kubernetes"`
	OpenStack   openstack_provider.AuthOpts `mapstructure:"openstack"`
	Terraform   terraformConfig             `mapstructure:"terraform"`
}

// Configuration for connecting to Kubernetes API server, either api_host or kubeconfig should be configured.
type kubeConfig struct {
	// (Optional)Kubernetes API server host address.
	ApiserverHost string `mapstructure:"api-host"`

	// (Optional)Kubeconfig file used to connect to Kubernetes cluster.
	KubeConfig string `mapstructure:"kubeconfig"`
}

// LBaaS related configuration
type terraformConfig struct {
	// (Optional) Provider name for the load balancer. Default: terraform
	// For more information: https://docs.openstack.org/terraform/latest/admin/providers.html
	Provider string `mapstructure:"provider"`

	// (Required) Subnet ID to create the load balancer.
	SubnetID string `mapstructure:"subnet-id"`

	// (Optional) Public network ID to create floating IP.
	// If empty, no floating IP will be allocated to the load balancer vip.
	FloatingIPNetworkID string `mapstructure:"floating-network-id"`

	// (Optional) Public subnet ID to create floating IP.
	// If empty, the first available will be used
	FloatingIPSubnetID string `mapstructure:"floating-subnet-id"`

	// (Optional) If the ingress controller should manage the security groups attached to the cluster nodes.
	// Default is false.
	ManageSecurityGroups bool `mapstructure:"manage-security-groups"`

	CreateMonitor     bool   `mapstructure:"create-monitor"`
	MonitorDelay      string `mapstructure:"monitor-delay"`
	MonitorTimeout    string `mapstructure:"monitor-timeout"`
	MonitorMaxRetries uint   `mapstructure:"monitor-max-retries"`
}
