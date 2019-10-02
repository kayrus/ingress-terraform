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

package controller

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	apiv1 "k8s.io/api/core/v1"
	nwv1beta1 "k8s.io/api/networking/v1beta1"
	apimetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	extlisters "k8s.io/client-go/listers/networking/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/kayrus/ingress-terraform/pkg/ingress/config"
	"github.com/kayrus/ingress-terraform/pkg/ingress/controller/terraform"
	"github.com/kayrus/ingress-terraform/pkg/ingress/utils"
)

const (
	// High enough QPS to fit all expected use cases. QPS=0 is not set here, because
	// client code is overriding it.
	defaultQPS = 1e6
	// High enough Burst to fit all expected use cases. Burst=0 is not set here, because
	// client code is overriding it.
	defaultBurst = 1e6

	maxRetries = 5

	// IngressKey picks a specific "class" for the Ingress.
	// The controller only processes Ingresses with this annotation either
	// unset, or set to either the configured value or the empty string.
	IngressKey = "kubernetes.io/ingress.class"

	// IngressClass menas accept ingresses with the annotation
	IngressClass = "terraform"

	// LabelNodeRoleMaster specifies that a node is a master
	// It's copied over to kubeadm until it's merged in core: https://github.com/kubernetes/kubernetes/pull/39112
	LabelNodeRoleMaster = "node-role.kubernetes.io/master"

	// IngressAnnotationInternal is the annotation used on the Ingress
	// to indicate that we want an internal loadbalancer service so that terraform-ingress-controller won't associate
	// floating ip to the load balancer VIP.
	// Default to true.
	IngressAnnotationInternal = "terraform.ingress.kubernetes.io/internal"

	// The IngressControllerTag that is added to the related resources.
	IngressControllerTag = "terraform.ingress.kubernetes.io"
)

// EventType type of event associated with an informer
type EventType string

const (
	// CreateEvent event associated with new objects in an informer
	CreateEvent EventType = "CREATE"
	// UpdateEvent event associated with an object update in an informer
	UpdateEvent EventType = "UPDATE"
	// DeleteEvent event associated when an object is removed from an informer
	DeleteEvent EventType = "DELETE"
)

// Event holds the context of an event
type Event struct {
	Type EventType
	Obj  interface{}
}

// Controller ...
type Controller struct {
	stopCh                chan struct{}
	knownNodes            []*apiv1.Node
	queue                 workqueue.RateLimitingInterface
	informer              informers.SharedInformerFactory
	recorder              record.EventRecorder
	ingressLister         extlisters.IngressLister
	ingressListerSynced   cache.InformerSynced
	serviceLister         corelisters.ServiceLister
	serviceListerSynced   cache.InformerSynced
	secretLister          corelisters.SecretLister
	secretListerSynced    cache.InformerSynced
	configMapLister       corelisters.ConfigMapLister
	configMapListerSynced cache.InformerSynced
	nodeLister            corelisters.NodeLister
	nodeListerSynced      cache.InformerSynced
	kubeClient            kubernetes.Interface
	config                config.Config
	terraform             terraform.Terraform
}

// IsValid returns true if the given Ingress either doesn't specify
// the ingress.class annotation, or it's set to the configured in the
// ingress controller.
func IsValid(ing *nwv1beta1.Ingress) bool {
	ingress, ok := ing.GetAnnotations()[IngressKey]
	if !ok {
		log.WithFields(log.Fields{
			"ingress_name": ing.Name, "ingress_ns": ing.Namespace,
		}).Info("annotation not present in ingress")
		return false
	}

	return ingress == IngressClass
}

func createApiserverClient(apiserverHost string, kubeConfig string) (*kubernetes.Clientset, error) {
	cfg, err := clientcmd.BuildConfigFromFlags(apiserverHost, kubeConfig)
	if err != nil {
		return nil, err
	}

	cfg.QPS = defaultQPS
	cfg.Burst = defaultBurst
	cfg.ContentType = "application/vnd.kubernetes.protobuf"

	log.Debug("creating kubernetes API client")

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	v, err := client.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{
		"version": fmt.Sprintf("v%v.%v", v.Major, v.Minor),
	}).Debug("kubernetes API client created")

	return client, nil
}

func readyWorkerNodePredicate(node *apiv1.Node) bool {
	// We add the master to the node list, but its unschedulable.  So we use this to filter
	// the master.
	if node.Spec.Unschedulable {
		return false
	}

	// As of 1.6, we will taint the master, but not necessarily mark it unschedulable.
	// Recognize nodes labeled as master, and filter them also, as we were doing previously.
	if _, hasMasterRoleLabel := node.Labels[LabelNodeRoleMaster]; hasMasterRoleLabel {
		return false
	}

	// If we have no info, don't accept
	if len(node.Status.Conditions) == 0 {
		return false
	}
	for _, cond := range node.Status.Conditions {
		// We consider the node for load balancing only when its NodeReady condition status
		// is ConditionTrue
		if cond.Type == apiv1.NodeReady && cond.Status != apiv1.ConditionTrue {
			log.WithFields(log.Fields{"name": node.Name, "status": cond.Status}).Info("ignoring node")
			return false
		}
	}
	return true
}

// NewController creates a new OpenStack Ingress controller.
func NewController(conf config.Config) *Controller {
	// initialize k8s client
	kubeClient, err := createApiserverClient(conf.Kubernetes.ApiserverHost, conf.Kubernetes.KubeConfig)
	if err != nil {
		log.WithFields(log.Fields{
			"api_server":  conf.Kubernetes.ApiserverHost,
			"kuberconfig": conf.Kubernetes.KubeConfig,
			"error":       err,
		}).Fatal("failed to initialize kubernetes client")
	}

	/* TERRA: check credentials
	// initialize openstack client
	var osClient *openstack.OpenStack
	osClient, err = openstack.NewOpenStack(conf)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("failed to initialize openstack client")
	}
	*/

	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClient, time.Second*30)
	serviceInformer := kubeInformerFactory.Core().V1().Services()
	secretInformer := kubeInformerFactory.Core().V1().Secrets()
	configMapInformer := kubeInformerFactory.Core().V1().ConfigMaps()
	nodeInformer := kubeInformerFactory.Core().V1().Nodes()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: kubeClient.CoreV1().Events(""),
	})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{Component: "openstack-ingress-controller"})

	controller := &Controller{
		config:                conf,
		queue:                 queue,
		stopCh:                make(chan struct{}),
		informer:              kubeInformerFactory,
		recorder:              recorder,
		serviceLister:         serviceInformer.Lister(),
		serviceListerSynced:   serviceInformer.Informer().HasSynced,
		secretLister:          secretInformer.Lister(),
		secretListerSynced:    secretInformer.Informer().HasSynced,
		configMapLister:       configMapInformer.Lister(),
		configMapListerSynced: configMapInformer.Informer().HasSynced,
		nodeLister:            nodeInformer.Lister(),
		nodeListerSynced:      nodeInformer.Informer().HasSynced,
		knownNodes:            []*apiv1.Node{},
		kubeClient:            kubeClient,
	}

	//TODO: watch for the TLS key update
	//TODO: watch for the node update
	//TODO: watch for the configmap update

	ingInformer := kubeInformerFactory.Networking().V1beta1().Ingresses()
	ingInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng := obj.(*nwv1beta1.Ingress)
			key := fmt.Sprintf("%s/%s", addIng.Namespace, addIng.Name)

			if !IsValid(addIng) {
				log.Infof("ignore ingress %s", key)
				return
			}

			recorder.Event(addIng, apiv1.EventTypeNormal, "Creating", fmt.Sprintf("Ingress %s", key))
			controller.queue.AddRateLimited(Event{Obj: addIng, Type: CreateEvent})
		},
		UpdateFunc: func(old, new interface{}) {
			newIng := new.(*nwv1beta1.Ingress)
			oldIng := old.(*nwv1beta1.Ingress)
			if newIng.ResourceVersion == oldIng.ResourceVersion {
				// Periodic resync will send update events for all known Ingresses.
				// Two different versions of the same Ingress will always have different RVs.
				return
			}

			key := fmt.Sprintf("%s/%s", newIng.Namespace, newIng.Name)
			validOld := IsValid(oldIng)
			validCur := IsValid(newIng)
			changed := !reflect.DeepEqual(newIng.Spec, oldIng.Spec) || !reflect.DeepEqual(newIng.ObjectMeta.Annotations, oldIng.ObjectMeta.Annotations)
			if !validOld && validCur {
				recorder.Event(newIng, apiv1.EventTypeNormal, "Creating", fmt.Sprintf("Ingress %s", key))
				controller.queue.AddRateLimited(Event{Obj: newIng, Type: CreateEvent})
			} else if validOld && !validCur {
				recorder.Event(newIng, apiv1.EventTypeNormal, "Deleting", fmt.Sprintf("Ingress %s", key))
				controller.queue.AddRateLimited(Event{Obj: newIng, Type: DeleteEvent})
			} else if validCur && changed {
				recorder.Event(newIng, apiv1.EventTypeNormal, "Updating", fmt.Sprintf("Ingress %s", key))
				controller.queue.AddRateLimited(Event{Obj: newIng, Type: UpdateEvent})
			} else {
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			delIng, ok := obj.(*nwv1beta1.Ingress)
			if !ok {
				// If we reached here it means the ingress was deleted but its final state is unrecorded.
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Errorf("couldn't get object from tombstone %#v", obj)
					return
				}
				delIng, ok = tombstone.Obj.(*nwv1beta1.Ingress)
				if !ok {
					log.Errorf("Tombstone contained object that is not an Ingress: %#v", obj)
					return
				}
			}

			key := fmt.Sprintf("%s/%s", delIng.Namespace, delIng.Name)
			if !IsValid(delIng) {
				log.Infof("ignore ingress %s", key)
				return
			}

			recorder.Event(delIng, apiv1.EventTypeNormal, "Deleting", fmt.Sprintf("Ingress %s", key))
			controller.queue.AddRateLimited(Event{Obj: delIng, Type: DeleteEvent})
		},
	})

	controller.ingressLister = ingInformer.Lister()
	controller.ingressListerSynced = ingInformer.Informer().HasSynced

	return controller
}

// Start starts the openstack ingress controller.
func (c *Controller) Start() {
	defer close(c.stopCh)
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	log.Debug("starting Ingress controller")
	go c.informer.Start(c.stopCh)

	// wait for the caches to synchronize before starting the worker
	if !cache.WaitForCacheSync(c.stopCh, c.ingressListerSynced, c.serviceListerSynced, c.secretListerSynced, c.configMapListerSynced, c.nodeListerSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}
	log.Info("ingress controller synced and ready")

	readyWorkerNodes, err := c.nodeLister.ListWithPredicate(readyWorkerNodePredicate)
	if err != nil {
		log.Errorf("Failed to retrieve current set of nodes from node lister: %v", err)
		return
	}
	c.knownNodes = readyWorkerNodes

	// TODO: test with parallel workers, make sure to run one worker per LB
	// for i := 0; i < 5; i++ {
	go wait.Until(c.runWorker, time.Second, c.stopCh)
	//}
	go wait.Until(c.nodeSyncLoop, 60*time.Second, c.stopCh)

	<-c.stopCh
}

// nodeSyncLoop handles updating the hosts pointed to by all load
// balancers whenever the set of nodes in the cluster changes.
func (c *Controller) nodeSyncLoop() {
	readyWorkerNodes, err := c.nodeLister.ListWithPredicate(readyWorkerNodePredicate)
	if err != nil {
		log.Errorf("Failed to retrieve current set of nodes from node lister: %v", err)
		return
	}
	if utils.NodeSlicesEqual(readyWorkerNodes, c.knownNodes) {
		return
	}

	log.Infof("Detected change in list of current cluster nodes. New node set: %v", utils.NodeNames(readyWorkerNodes))

	// if no new nodes, then avoid update member
	if len(readyWorkerNodes) == 0 {
		c.knownNodes = readyWorkerNodes
		log.Info("Finished to handle node change, it's [] now")
		return
	}

	ings := new(nwv1beta1.IngressList)
	// TODO: only take ingresses without ip address into consideration
	opts := apimetav1.ListOptions{}
	if ings, err = c.kubeClient.NetworkingV1beta1().Ingresses("").List(opts); err != nil {
		log.Errorf("Failed to retrieve current set of ingresses: %v", err)
		return
	}

	// Update each valid ingress
	for _, ing := range ings.Items {
		if !IsValid(&ing) {
			continue
		}

		log.WithFields(log.Fields{"ingress": ing.Name, "namespace": ing.Namespace}).Debug("Starting to handle ingress")

		if err = c.ensureIngress(&ing, readyWorkerNodes); err != nil {
			log.WithFields(log.Fields{"ingress": ing.Name}).Error("Failed to handle ingress")
			continue
		}

		log.WithFields(log.Fields{"ingress": ing.Name, "namespace": ing.Namespace}).Info("Finished to handle ingress")
	}

	c.knownNodes = readyWorkerNodes

	log.Info("Finished to handle node change")
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
		// continue looping
	}
}

func (c *Controller) processNextItem() bool {
	obj, quit := c.queue.Get()

	if quit {
		return false
	}
	defer c.queue.Done(obj)

	err := c.processItem(obj.(Event))
	if err == nil {
		// No error, reset the ratelimit counters
		c.queue.Forget(obj)
	} else if c.queue.NumRequeues(obj) < maxRetries {
		log.WithFields(log.Fields{"obj": obj, "error": err}).Error("Failed to process obj (will retry)")
		c.queue.AddRateLimited(obj)
	} else {
		// err != nil and too many retries
		log.WithFields(log.Fields{"obj": obj, "error": err}).Error("Failed to process obj (giving up)")
		c.queue.Forget(obj)
		utilruntime.HandleError(err)
	}

	return true
}

func (c *Controller) processItem(event Event) error {
	ing := event.Obj.(*nwv1beta1.Ingress)
	key := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)

	switch event.Type {
	case CreateEvent:
		log.WithFields(log.Fields{"ingress": key}).Info("ingress created, will create openstack resources")

		if err := c.ensureIngress(ing, nil); err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create openstack resources for ingress %s: %v", key, err))
			c.recorder.Event(ing, apiv1.EventTypeWarning, "Failed", fmt.Sprintf("Failed to create openstack resources for ingress %s: %v", key, err))
		} else {
			c.recorder.Event(ing, apiv1.EventTypeNormal, "Created", fmt.Sprintf("Ingress %s", key))
		}
	case UpdateEvent:
		log.WithFields(log.Fields{"ingress": key}).Info("ingress updated, will update openstack resources")

		if err := c.ensureIngress(ing, nil); err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to update openstack resources for ingress %s: %v", key, err))
			c.recorder.Event(ing, apiv1.EventTypeWarning, "Failed", fmt.Sprintf("Failed to update openstack resources for ingress %s: %v", key, err))
		} else {
			c.recorder.Event(ing, apiv1.EventTypeNormal, "Updated", fmt.Sprintf("Ingress %s", key))
		}
	case DeleteEvent:
		log.WithFields(log.Fields{"ingress": key}).Info("ingress has been deleted, will delete openstack resources")

		if err := c.deleteIngress(ing); err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to delete openstack resources for ingress %s: %v", key, err))
			c.recorder.Event(ing, apiv1.EventTypeWarning, "Failed", fmt.Sprintf("Failed to delete openstack resources for ingress %s: %v", key, err))
		} else {
			c.recorder.Event(ing, apiv1.EventTypeNormal, "Deleted", fmt.Sprintf("Ingress %s", key))
		}
	}

	return nil
}

func (c *Controller) deleteIngress(ing *nwv1beta1.Ingress) error {
	lbUID := "a" + strings.Replace(string(ing.UID), "-", "", -1)
	lb := terraform.Terraform{
		AuthOpts:        &c.config.OpenStack,
		LoadBalancerUID: lbUID,
	}

	return c.terraform.DeleteLoadbalancer(lb, c.kubeClient.CoreV1(), ing.ObjectMeta.Namespace)
}

func (c *Controller) getServiceNodePort(name string, port intstr.IntOrString) (int, error) {
	svc, err := c.getService(name)
	if err != nil {
		return 0, err
	}

	var nodePort int
	ports := svc.Spec.Ports
	for _, p := range ports {
		// Only TCP ports are supported
		if p.Protocol == apiv1.ProtocolTCP {
			if port.Type == intstr.Int && int(p.Port) == port.IntValue() {
				nodePort = int(p.NodePort)
				break
			}
			if port.Type == intstr.String && p.Name == port.StrVal {
				nodePort = int(p.NodePort)
				break
			}
		}
	}

	if nodePort == 0 {
		return 0, fmt.Errorf("failed to find service node port")
	}

	return nodePort, nil
}

func getNodeAddressForLB(node *apiv1.Node) (string, error) {
	addrs := node.Status.Addresses
	if len(addrs) == 0 {
		return "", fmt.Errorf("no address found for host")
	}

	for _, addr := range addrs {
		if addr.Type == apiv1.NodeInternalIP {
			return addr.Address, nil
		}
	}

	return addrs[0].Address, nil
}

func getNodeNameForLB(node *apiv1.Node) (string, error) {
	addrs := node.Status.Addresses
	if len(addrs) == 0 {
		return "", fmt.Errorf("no address found for host")
	}

	for _, addr := range addrs {
		if addr.Type == apiv1.NodeHostName {
			return addr.Address, nil
		}
	}

	return addrs[0].Address, nil
}

func secretExists(tls *[]terraform.TLS, name string) bool {
	for _, t := range *tls {
		if t.Name == name {
			log.Printf("%q secret already fetched", name)
			return true
		}
	}
	return false
}

func poolExists(pools *[]terraform.Pool, name string) bool {
	for _, p := range *pools {
		if p.Name == name {
			log.Printf("%q pool already exists", name)
			return true
		}
	}
	return false
}

func tcpPortExists(tcpPorts *[]terraform.TCP, port int) bool {
	for _, p := range *tcpPorts {
		if p.Port == port {
			log.Printf("%q port already exists", port)
			return true
		}
	}
	return false
}

func (c *Controller) ensureIngress(ing *nwv1beta1.Ingress, nodes []*apiv1.Node) error {
	var err error
	ingName := ing.ObjectMeta.Name
	ingNamespace := ing.ObjectMeta.Namespace
	clusterName := c.config.ClusterName
	lbUID := "a" + strings.Replace(string(ing.UID), "-", "", -1)

	if c.config.Terraform.SubnetID == "" {
		return fmt.Errorf("SubnetID is not defined")
	}

	key := fmt.Sprintf("%s/%s", ingNamespace, ingName)
	name := utils.GetResourceName(ingNamespace, ingName, clusterName)
	description := fmt.Sprintf("Kubernetes Ingress %s in namespace %s from cluster %s", ingName, ingNamespace, clusterName)

	if nodes == nil {
		// get nodes information
		nodes, err = c.nodeLister.ListWithPredicate(readyWorkerNodePredicate)
		if err != nil {
			return err
		}
	}

	internalSetting := getStringFromIngressAnnotation(ing, IngressAnnotationInternal, "true")
	isInternal, err := strconv.ParseBool(internalSetting)
	if err != nil {
		return fmt.Errorf("unknown annotation %s: %v", IngressAnnotationInternal, err)
	}

	if !isInternal {
		if c.config.Terraform.FloatingIPNetworkID != "" {
			log.WithFields(log.Fields{"ingress": key}).Info("creating floating IP")
		} else {
			log.WithFields(log.Fields{"ingress": key}).Info("forcing isInternal, because floating network ID is not defined")
			isInternal = true
		}
	}

	lb := terraform.Terraform{
		AuthOpts:                &c.config.OpenStack,
		LoadBalancerUID:         lbUID,
		LoadBalancerName:        name,
		LoadBalancerDescription: description,
		LoadBalancerProvider:    c.config.Terraform.Provider,
		SubnetID:                c.config.Terraform.SubnetID,
		FloatingIPNetworkID:     c.config.Terraform.FloatingIPNetworkID,
		FloatingIPSubnetID:      c.config.Terraform.FloatingIPSubnetID,
		IsInternal:              isInternal,
		ManageSecurityGroups:    c.config.Terraform.ManageSecurityGroups,
		Monitor: terraform.Monitor{
			CreateMonitor: c.config.Terraform.CreateMonitor,
			Delay:         c.config.Terraform.MonitorDelay,
			Timeout:       c.config.Terraform.MonitorTimeout,
			MaxRetries:    c.config.Terraform.MonitorMaxRetries,
		},
	}

	if ing.Spec.TLS != nil {
		for _, v := range ing.Spec.TLS {
			secretName := fmt.Sprintf("%s/%s", ingNamespace, v.SecretName)
			lbSecretName := fmt.Sprintf("%s_%s", ingNamespace, v.SecretName)

			if secretExists(&lb.TLS, lbSecretName) {
				continue
			}

			secret, err := c.getSecret(secretName)
			if err != nil {
				return err
			}

			cert, ok := secret.Data[apiv1.TLSCertKey]
			if !ok {
				return fmt.Errorf("failed to get the %q secret certificate", secretName)
			}

			key, ok := secret.Data[apiv1.TLSPrivateKeyKey]
			if !ok {
				return fmt.Errorf("failed to get the %q secret certificate", secretName)
			}

			tls := terraform.TLS{
				Name:        lbSecretName,
				Certificate: string(cert),
				Key:         string(key),
			}
			lb.TLS = append(lb.TLS, tls)
		}
		if len(lb.TLS) > 0 {
			lb.CreateTLS = true
		}
	}

	if ing.Spec.Backend != nil {
		serviceName := fmt.Sprintf("%s/%s", ingNamespace, ing.Spec.Backend.ServiceName)
		poolName := fmt.Sprintf("pool_%s_%s_%s", ingNamespace, ing.Spec.Backend.ServiceName, ing.Spec.Backend.ServicePort.String())

		nodePort, err := c.getServiceNodePort(serviceName, ing.Spec.Backend.ServicePort)
		if err != nil {
			return err
		}

		pool := terraform.Pool{
			Primary:  true,
			Name:     poolName,
			Protocol: "HTTP",
			Method:   "ROUND_ROBIN",
		}

		if pool.Members, err = convertNodesToMembers(nodes, nodePort); err != nil {
			return fmt.Errorf("failed to convert a node list to a member list: %v", err)
		}

		lb.Pools = append(lb.Pools, pool)
	}

	// Add l7 load balancing rules. Each host and path combination is mapped to a l7 policy,
	// which contains two rules(with type 'HOST_NAME' and 'PATH' respectively)
	for _, rule := range ing.Spec.Rules {
		host := rule.Host

		for _, path := range rule.HTTP.Paths {
			serviceName := fmt.Sprintf("%s/%s", ingNamespace, path.Backend.ServiceName)
			poolName := fmt.Sprintf("pool_%s_%s_%s", ingNamespace, path.Backend.ServiceName, path.Backend.ServicePort.String())

			rule := terraform.Rule{
				PoolName: poolName,
				Path:     path.Path,
				Host:     host,
			}
			lb.Rules = append(lb.Rules, rule)

			if poolExists(&lb.Pools, poolName) {
				continue
			}

			nodePort, err := c.getServiceNodePort(serviceName, path.Backend.ServicePort)
			if err != nil {
				return err
			}

			pool := terraform.Pool{
				Name:     poolName,
				Protocol: "HTTP",
				Method:   "ROUND_ROBIN",
			}

			if pool.Members, err = convertNodesToMembers(nodes, nodePort); err != nil {
				return fmt.Errorf("failed to convert a node list to a member list: %v", err)
			}

			lb.Pools = append(lb.Pools, pool)
		}
	}

	// Direct TCP
	// TODO: watch for configmap modifications
	configMapName := fmt.Sprintf("%s/%s", ingNamespace, "ingress-tcp-services") // TODO: parametrize
	if v, err := c.getConfigMap(configMapName); err != nil {
		log.Printf("Failed to get the %q configmap, ignoring TCP listeners: %v", configMapName, err)
	} else {
		for port, svc := range v.Data {
			tcpPort, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("failed to convert the %q to a number: %v", port, err)
			}

			// check tcp port
			if tcpPort == 80 || tcpPort == 443 {
				return fmt.Errorf("the 80 or 443 ports are not allowed")
			}
			if tcpPort < 1 || tcpPort > 65535 {
				return fmt.Errorf("the %d port is out of range", tcpPort)
			}
			if tcpPortExists(&lb.TCP, tcpPort) {
				return fmt.Errorf("the %d port is already defined", tcpPort)
			}

			s := strings.SplitN(svc, ":", 2)
			if len(s) != 2 {
				return fmt.Errorf("failed to parse the %q to a service name and a port", svc)
			}

			serviceName := fmt.Sprintf("%s/%s", ingNamespace, s[0])
			poolName := fmt.Sprintf("tcp_pool_%s_%s_%s", ingNamespace, s[0], s[1])

			nodePort, err := c.getServiceNodePort(serviceName, intstr.Parse(s[1]))
			if err != nil {
				return err
			}

			lb.TCP = append(lb.TCP, terraform.TCP{
				PoolName: poolName,
				Port:     tcpPort,
			})

			if poolExists(&lb.Pools, poolName) {
				continue
			}

			pool := terraform.Pool{
				Name:     poolName,
				Protocol: "TCP",
				Method:   "ROUND_ROBIN",
			}

			if pool.Members, err = convertNodesToMembers(nodes, nodePort); err != nil {
				return fmt.Errorf("failed to convert a node list to a member list: %v", err)
			}

			lb.Pools = append(lb.Pools, pool)
		}
	}

	// TODO: parametrize the configmap name and watch for its modification
	ipAddress, err := c.terraform.EnsureLoadBalancer(lb, c.kubeClient.CoreV1(), ingNamespace, "terraform-template")
	if err != nil {
		return err
	}

	_, err = c.updateIngressStatus(ing, ipAddress)
	if err != nil {
		return err
	}
	c.recorder.Event(ing, apiv1.EventTypeNormal, "Updated", fmt.Sprintf("Successfully associated IP address %s to ingress %s", ipAddress, key))

	log.WithFields(log.Fields{"ingress": key, "lbID": "terraform"}).Info("openstack resources for ingress created")

	return nil
}

func (c *Controller) updateIngressStatus(ing *nwv1beta1.Ingress, vip string) (*nwv1beta1.Ingress, error) {
	newState := new(apiv1.LoadBalancerStatus)
	newState.Ingress = []apiv1.LoadBalancerIngress{{IP: vip}}
	newIng := ing.DeepCopy()
	newIng.Status.LoadBalancer = *newState

	newObj, err := c.kubeClient.NetworkingV1beta1().Ingresses(newIng.Namespace).UpdateStatus(newIng)
	if err != nil {
		return nil, err
	}

	return newObj, nil
}

func (c *Controller) getService(key string) (*apiv1.Service, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, err
	}

	service, err := c.serviceLister.Services(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	return service, nil
}

func (c *Controller) getSecret(key string) (*apiv1.Secret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, err
	}

	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (c *Controller) getConfigMap(key string) (*apiv1.ConfigMap, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, err
	}

	configMap, err := c.configMapLister.ConfigMaps(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	return configMap, nil
}

func convertNodesToMembers(nodes []*apiv1.Node, nodePort int) ([]terraform.Member, error) {
	members := make([]terraform.Member, len(nodes))
	for i, node := range nodes {
		address, err := getNodeAddressForLB(node)
		if err != nil {
			return nil, err
		}
		name, err := getNodeNameForLB(node)
		if err != nil {
			return nil, err
		}
		nodeID, err := utils.GetNodeID(node)
		if err != nil {
			return nil, err
		}
		member := terraform.Member{
			NodeID:  nodeID,
			Name:    "m" + name,
			Address: address,
			Port:    nodePort,
		}
		members[i] = member
	}

	return members, nil
}

// getStringFromIngressAnnotation searches a given Ingress for a specific annotationKey and either returns the
// annotation's value or a specified defaultSetting
func getStringFromIngressAnnotation(ingress *nwv1beta1.Ingress, annotationKey string, defaultValue string) string {
	if annotationValue, ok := ingress.Annotations[annotationKey]; ok {
		return annotationValue
	}

	return defaultValue
}
