package terraform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"text/template"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apimetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	openstack_provider "k8s.io/cloud-provider-openstack/pkg/cloudprovider/providers/openstack"
)

const tfStateName = "terraform.tfstate"

type State struct {
	Output struct {
		LbIP struct {
			Value string `json:"value,omitempty"`
		} `json:"lb_ip,omitempty"`
	} `json:"outputs,omitempty"`
}

// Terraform is an implementation of cloud provider Interface for Terraform.
type Terraform struct {
	AuthOpts                *openstack_provider.AuthOpts
	SkipHTTP                bool
	LoadBalancerUID         string
	LoadBalancerName        string
	LoadBalancerDescription string
	LoadBalancerProvider    string
	SubnetID                string
	IsInternal              bool
	FloatingIPNetworkID     string
	FloatingIPSubnetID      string
	ManageSecurityGroups    bool
	Pools                   []Pool
	Rules                   []Rule
	TCP                     []Port
	UDP                     []Port
	Monitor                 Monitor
	CreateTLS               bool
	TLS                     []TLS
}

type Rule struct {
	PoolName string
	Path     string
	Host     string
}

type Port struct {
	PoolName string
	Port     int
}

type Pool struct {
	Name     string
	Primary  bool
	Protocol string
	Method   string
	Members  []Member
}

type Member struct {
	NodeID  string
	Name    string
	Address string
	Port    int
}

type Monitor struct {
	CreateMonitor bool
	Delay         string
	Timeout       string
	MaxRetries    uint
}

type TLS struct {
	Name        string
	Certificate string
	Key         string
}

func authOptsToEnv(opts *openstack_provider.AuthOpts) []string {
	return []string{
		fmt.Sprintf("OS_AUTH_URL=%s", opts.AuthURL),
		fmt.Sprintf("OS_USER_ID=%s", opts.UserID),
		fmt.Sprintf("OS_USERNAME=%s", opts.Username),
		fmt.Sprintf("OS_PASSWORD=%s", opts.Password),
		fmt.Sprintf("OS_PROJECT_ID=%s", opts.TenantID),
		fmt.Sprintf("OS_PROJECT_NAME=%s", opts.TenantName),
		fmt.Sprintf("OS_DOMAIN_ID=%s", opts.DomainID),
		fmt.Sprintf("OS_DOMAIN_NAME=%s", opts.DomainName),
		fmt.Sprintf("OS_PROJECT_DOMAIN_ID=%s", opts.TenantDomainID),
		fmt.Sprintf("OS_PROJECT_DOMAIN_NAME=%s", opts.TenantDomainName),
		fmt.Sprintf("OS_USER_DOMAIN_ID=%s", opts.UserDomainID),
		fmt.Sprintf("OS_USER_DOMAIN_NAME=%s", opts.UserDomainName),
		fmt.Sprintf("OS_REGION_NAME=%s", opts.Region),
		fmt.Sprintf("OS_APPLICATION_CREDENTIAL_ID=%s", opts.ApplicationCredentialID),
		fmt.Sprintf("OS_APPLICATION_CREDENTIAL_NAME=%s", opts.ApplicationCredentialName),
		fmt.Sprintf("OS_APPLICATION_CREDENTIAL_SECRET=%s", opts.ApplicationCredentialSecret),
	}
}

func saveTerraformState(client v1core.SecretInterface, lbName string) (bool, error) {
	secretName := fmt.Sprintf("lb-tf-state-%s", lbName)
	dir := path.Join("/tmp", lbName)

	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return false, fmt.Errorf("failed to create the %q directory: %v", dir, err)
	}

	tfState, err := client.Get(secretName, apimetav1.GetOptions{})
	if err != nil {
		return true, fmt.Errorf("failed to get the terraform state for the %q secret: %v", secretName, err)
	}

	if state, ok := tfState.Data[tfStateName]; !ok {
		return true, fmt.Errorf("failed to get the terraform state from the %q secret: %v", secretName, err)
	} else {
		tfStateFileName := path.Join(dir, tfStateName)
		err = ioutil.WriteFile(tfStateFileName, []byte(state), 0600)
		if err != nil {
			return false, fmt.Errorf("failed to save the terraform state to the %q: %v", tfStateFileName, err)
		}
	}

	return true, nil
}

func getTerraformTemplate(client v1core.ConfigMapInterface, name string) (string, error) {
	t, err := client.Get(name, apimetav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get the %q terraform template: %v", name, err)
	}

	if v, ok := t.Data["template"]; ok {
		return v, nil
	}

	return "", fmt.Errorf("failed to get the terraform template from the %q configmap: %v", name, err)
}

func readIP(lbName string) (string, error) {
	dir := path.Join("/tmp", lbName)
	tfStateFileName := path.Join(dir, tfStateName)

	state, err := ioutil.ReadFile(tfStateFileName)
	if err != nil {
		return "", fmt.Errorf("failed to read the terraform state for the %q: %v", tfStateFileName, err)
	}

	output := State{}
	err = json.Unmarshal(state, &output)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal the loadbalancer IP: %v", err)
	}

	return output.Output.LbIP.Value, nil
}

func updateTerraformState(client v1core.SecretInterface, lbName string) error {
	secretName := fmt.Sprintf("lb-tf-state-%s", lbName)

	dir := path.Join("/tmp", lbName)
	tfStateFileName := path.Join(dir, tfStateName)

	state, err := ioutil.ReadFile(tfStateFileName)
	if err != nil {
		return fmt.Errorf("failed to read the terraform state for the %q: %v", tfStateFileName, err)
	}

	tsState := v1.Secret{}
	tsState.Labels = map[string]string{
		"ingress": "terraform",
	}
	tsState.Name = secretName
	tsState.Data = map[string][]byte{
		tfStateName: state,
	}

	_, err = client.Create(&tsState)
	if err != nil {
		log.Printf("failed to create the terraform state for the %q secret: %v", secretName, err)
		_, err = client.Update(&tsState)
		if err != nil {
			return fmt.Errorf("failed to update the terraform state for the %q secret: %v", secretName, err)
		}
	}

	return nil
}

func deleteTerraformState(client v1core.SecretInterface, lbName string) error {
	secretName := fmt.Sprintf("lb-tf-state-%s", lbName)

	err := client.Delete(secretName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete the terraform state %q secret", secretName)
	}

	return nil
}

func (*Terraform) DeleteLoadbalancer(lb Terraform, client v1core.CoreV1Interface, namespace string) error {
	_, err := saveTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
	if err != nil {
		return err
	}

	dir := path.Join("/tmp", lb.LoadBalancerUID)

	// this is needed in case when new ingress.tf is broken
	// terraform will rely on the state file only
	tfFile := path.Join(dir, "ingress.tf")
	_, err = os.Stat(tfFile)
	if !os.IsNotExist(err) {
		err = os.Remove(tfFile)
		if err != nil {
			return fmt.Errorf("failed to delete the terraform script from %q: %v", tfFile, err)
		}
	}

	init := exec.Command("terraform", "init")
	init.Dir = dir
	err = init.Run()
	if err != nil {
		return fmt.Errorf("failed to init the terraform: %v", err)
	}

	cmd := exec.Command("terraform", "destroy", "-auto-approve")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), authOptsToEnv(lb.AuthOpts)...)
	cmd.Dir = dir
	err = cmd.Run()
	if err != nil {
		e := updateTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
		if e != nil {
			log.Printf("Error during the state save: %v", e)
		}
		return fmt.Errorf("failed to run the terraform destroy: %v", err)
	}

	err = deleteTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
	if err != nil {
		log.Printf("%v", err)
	}

	return nil
}

func (*Terraform) EnsureLoadBalancer(lb Terraform, client v1core.CoreV1Interface, namespace string, templateCM string) (string, error) {
	okToCreate, err := saveTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
	if err != nil {
		if !okToCreate {
			return "", err
		}
		log.Printf("Assuming the new loadbalancer: %v", err)
	}

	dir := path.Join("/tmp", lb.LoadBalancerUID)

	var temp string
	if templateCM != "" {
		temp, err = getTerraformTemplate(client.ConfigMaps(namespace), templateCM)
		if err != nil {
			return "", err
		}
	} else {
		temp = defaultTemplate
	}

	var output bytes.Buffer
	t, err := template.New("terraform").Parse(temp)
	if err != nil {
		return "", fmt.Errorf("error parsing the template: %v", err)
	}
	err = t.Execute(&output, lb)
	if err != nil {
		return "", fmt.Errorf("error executing the template: %v", err)
	}

	tfFile := path.Join(dir, "ingress.tf")
	err = ioutil.WriteFile(tfFile, output.Bytes(), 0600)
	if err != nil {
		return "", fmt.Errorf("failed to save the terraform script to %q: %v", tfFile, err)
	}

	init := exec.Command("terraform", "init")
	init.Dir = dir
	init.Stdout = os.Stdout
	init.Stderr = os.Stderr
	init.Env = append(os.Environ(), authOptsToEnv(lb.AuthOpts)...)
	err = init.Run()
	if err != nil {
		return "", fmt.Errorf("failed to init the terraform: %v", err)
	}

	cmd := exec.Command("terraform", "apply", "-auto-approve")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), authOptsToEnv(lb.AuthOpts)...)
	for _, tls := range lb.TLS {
		// add certificates
		cmd.Env = append(cmd.Env, fmt.Sprintf("TF_VAR_%s_certificate=%s", tls.Name, tls.Certificate))
		cmd.Env = append(cmd.Env, fmt.Sprintf("TF_VAR_%s_private_key=%s", tls.Name, tls.Key))
	}
	err = cmd.Run()
	if err != nil {
		e := updateTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
		if e != nil {
			log.Printf("Error during the state save: %v", e)
		}
		return "", fmt.Errorf("failed to run the terraform apply: %v", err)
	}

	ip, err := readIP(lb.LoadBalancerUID)
	if err != nil {
		log.Printf("Failed to read the loadbalancer IP: %v", err)
	}

	return ip, updateTerraformState(client.Secrets(namespace), lb.LoadBalancerUID)
}
