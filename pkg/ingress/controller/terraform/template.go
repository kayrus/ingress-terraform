package terraform

const defaultTemplate = `
resource "openstack_lb_loadbalancer_v2" "{{ $.LoadBalancerUID }}" {
  name          = "{{ $.LoadBalancerName }}"
  description   = "{{ $.LoadBalancerDescription }}"
  vip_subnet_id = "{{ $.SubnetID }}"
{{- if ne $.LoadBalancerProvider "" }}
  loadbalancer_provider = "{{ $.LoadBalancerProvider }}"
{{- end }}
}

{{- if not $.IsInternal }}
data "openstack_networking_network_v2" "fip_network" {
  network_id = "{{ $.FloatingIPNetworkID }}"
}

resource "openstack_networking_floatingip_v2" "{{ $.LoadBalancerUID }}_fip" {
  pool        = "${data.openstack_networking_network_v2.fip_network.name}"
  subnet_id   = "{{ $.FloatingIPSubnetID }}"
  description = "Floating IP for Kubernetes ingress {{ $.LoadBalancerUID }} LB"
}

resource "openstack_networking_floatingip_associate_v2" "{{ $.LoadBalancerUID }}_fip_attach" {
  floating_ip = "${openstack_networking_floatingip_v2.{{ $.LoadBalancerUID }}_fip.address}"
  port_id     = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.vip_port_id}"
}
{{- end }}

{{- if $.ManageSecurityGroups }}
data "openstack_networking_subnet_v2" "lb_subnet" {
  subnet_id = "{{ $.FloatingIPSubnetID }}"
}
{{- end }}

{{- if ne $.SkipHTTP true }}
resource "openstack_lb_listener_v2" "http" {
  name            = "http"
  protocol        = "HTTP"
  protocol_port   = 80
  loadbalancer_id = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.id}"
{{- $default := false }}
{{- range $p := $.Pools }}
{{- if $p.Primary }}
{{- $default = true }}
  default_pool_id = "${openstack_lb_pool_v2.{{ $p.Name }}.id}"
{{- end }}
{{- end }}
{{- if ne $default true }}
  default_pool_id = null # BUG: https://github.com/terraform-providers/terraform-provider-openstack/issues/886
{{- end }}
}
{{- end }}

{{- if $.CreateTLS }}
{{- range $tls := $.TLS }}
variable "{{ $tls.Name }}_certificate" {
  default = ""
}
variable "{{ $tls.Name }}_private_key" {
  default = ""
}

resource "openstack_keymanager_secret_v1" "certificate_{{ $tls.Name }}" {
  name                 = "{{ $tls.Name }}_certificate"
  payload              = "${var.{{ $tls.Name }}_certificate}"
  secret_type          = "certificate"
  payload_content_type = "text/plain"
}

resource "openstack_keymanager_secret_v1" "private_key_{{ $tls.Name }}" {
  name                 = "{{ $tls.Name }}_private_key"
  payload              = "${var.{{ $tls.Name }}_private_key}"
  secret_type          = "private"
  payload_content_type = "text/plain"
}

locals {
  # recreate the container once the cert has been updated
  tls_container_name = "{{ $tls.Name }}_${substr(openstack_keymanager_secret_v1.certificate_{{ $tls.Name }}.id, 0, 3)}${substr(openstack_keymanager_secret_v1.private_key_{{ $tls.Name }}.id, 0, 3)}"
}

resource "openstack_keymanager_container_v1" "tls_{{ $tls.Name }}" {
  name = "${local.tls_container_name}"
  type = "certificate"

  secret_refs {
    name       = "certificate"
    secret_ref = "${openstack_keymanager_secret_v1.certificate_{{ $tls.Name }}.secret_ref}"
  }

  secret_refs {
    name       = "private_key"
    secret_ref = "${openstack_keymanager_secret_v1.private_key_{{ $tls.Name }}.secret_ref}"
  }

  lifecycle {
    create_before_destroy = true
  }
}
{{- end }}

resource "openstack_lb_listener_v2" "https" {
  name            = "https"
  protocol        = "TERMINATED_HTTPS"
  protocol_port   = 443
  loadbalancer_id = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.id}"
{{- range $i, $tls := $.TLS }}
{{ if eq $i 0 }}
  default_tls_container_ref = "${openstack_keymanager_container_v1.tls_{{ $tls.Name }}.container_ref}" # TODO: add golang template break
{{- end }}
{{- end }}
{{- range $p := $.Pools }}
{{- if $p.Primary }}
  default_pool_id = "${openstack_lb_pool_v2.{{ $p.Name }}.id}"
{{- end }}
{{- end }}
  sni_container_refs = [
{{- range $i, $tls := $.TLS }}
{{ if ne $i 0 }}
    "${openstack_keymanager_container_v1.tls_{{ $tls.Name }}.container_ref}",
{{- end }}
{{- end }}
  ]
}
{{- end }}

{{- range $port := $.TCP }}
resource "openstack_lb_listener_v2" "{{ $port.PoolName }}_{{ $port.Port }}" {
  name            = "{{ $port.PoolName }}"
  protocol        = "TCP"
  protocol_port   = {{ $port.Port }}
  loadbalancer_id = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.id}"
{{- range $p := $.Pools }}
{{- if eq $p.Name $port.PoolName }}
  default_pool_id = "${openstack_lb_pool_v2.{{ $port.PoolName }}.id}"
{{- end }}
{{- end }}
}
{{- end }}

{{- range $port := $.UDP }}
resource "openstack_lb_listener_v2" "{{ $port.PoolName }}_{{ $port.Port }}" {
  name            = "{{ $port.PoolName }}"
  protocol        = "UDP"
  protocol_port   = {{ $port.Port }}
  loadbalancer_id = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.id}"
{{- range $p := $.Pools }}
{{- if eq $p.Name $port.PoolName }}
  default_pool_id = "${openstack_lb_pool_v2.{{ $port.PoolName }}.id}"
{{- end }}
{{- end }}
}
{{- end }}

{{- range $p := $.Pools }}
resource "openstack_lb_pool_v2" "{{ $p.Name }}" {
  name            = "{{ $p.Name }}"
  protocol        = "{{ $p.Protocol }}"
  lb_method       = "{{ $p.Method }}"
  loadbalancer_id = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.id}"
}

{{- if $.ManageSecurityGroups }}
resource "openstack_networking_secgroup_v2" "sg_pool_{{ $p.Name }}" {
  name        = "sg_pool_{{ $p.Name }}"
  description = "Security group for the {{ $p.Name }} pool"
}
{{- end }}

{{- range $k, $m := $p.Members }}
resource "openstack_lb_member_v2" "{{ $p.Name }}_{{ $m.Name }}" {
  name          = "{{ $m.Name }}"
  address       = "{{ $m.Address }}"
  pool_id       = "${openstack_lb_pool_v2.{{ $p.Name }}.id}"
  protocol_port = "{{ $m.Port }}"
  subnet_id     = "{{ $.SubnetID }}"
}

{{- if $.ManageSecurityGroups }}
{{- if eq $k 0 }}
# all k8s nodePorts have the same port
resource "openstack_networking_secgroup_rule_v2" "sg_rule_pool_{{ $p.Name }}" {
  direction         = "ingress"
  ethertype         = "IPv4"
{{- if eq $p.Protocol "UDP" }}
  protocol          = "udp"
{{- else }}
  protocol          = "tcp"
{{- end }}
  port_range_min    = "{{ $m.Port }}"
  port_range_max    = "{{ $m.Port }}"
  remote_ip_prefix  = "${data.openstack_networking_subnet_v2.lb_subnet.cidr}"
  security_group_id = "${openstack_networking_secgroup_v2.sg_pool_{{ $p.Name }}.id}"
}
{{- end }}

data "openstack_networking_port_ids_v2" "server_ports_{{ $p.Name }}_{{ $m.Name }}" {
  device_id = "{{ $m.NodeID }}"
}
{{- end }}
{{- end }}

{{- if $.Monitor.CreateMonitor }}
resource "openstack_lb_monitor_v2" "monitor_{{ $p.Name }}" {
  name           = "monitor_{{ $p.Name }}"
  pool_id        = "${openstack_lb_pool_v2.{{ $p.Name }}.id}"
{{- if eq $p.Protocol "UDP" }}
  type           = "UDP-CONNECT"
{{- else }}
  type           = "TCP"
{{- end }}
  delay          = "{{ $.Monitor.Delay }}"
  timeout        = "{{ $.Monitor.Timeout }}"
  max_retries    = "{{ $.Monitor.MaxRetries }}"
}
{{- end }}
{{- end }}

{{- range $i, $r := $.Rules }}
{{- if or (ne $r.Path "") (ne $r.Host "") }}
{{- if ne $.SkipHTTP true }}
resource "openstack_lb_l7policy_v2" "http_{{ $r.PoolName }}_{{ $i }}" {
  name             = "http_{{ $r.PoolName }}_{{ $i }}"
  description      = "Created by kubernetes ingress"
  action           = "REDIRECT_TO_POOL"
  # Force re-create pool depencency workaround, for destroy as well
  listener_id      = "${openstack_lb_listener_v2.http.id}${ openstack_lb_pool_v2.{{ $r.PoolName }}.id == "" ? "" : "" }"
  redirect_pool_id = "${openstack_lb_pool_v2.{{ $r.PoolName }}.id}"
}
{{- end }}

{{- if $.CreateTLS }}
resource "openstack_lb_l7policy_v2" "https_{{ $r.PoolName }}_{{ $i }}" {
  name             = "https_{{ $r.PoolName }}_{{ $i }}"
  description      = "Created by kubernetes ingress"
  action           = "REDIRECT_TO_POOL"
  # Force re-create pool depencency workaround, for destroy as well
  listener_id      = "${openstack_lb_listener_v2.https.id}${ openstack_lb_pool_v2.{{ $r.PoolName }}.id == "" ? "" : "" }"
  redirect_pool_id = "${openstack_lb_pool_v2.{{ $r.PoolName }}.id}"
}
{{- end }}

{{- if ne $r.Path "" }}
{{- if ne $.SkipHTTP true }}
resource "openstack_lb_l7rule_v2" "http_rule_path_{{ $r.PoolName }}_{{ $i }}" {
  l7policy_id  = "${openstack_lb_l7policy_v2.http_{{ $r.PoolName }}_{{ $i }}.id}"
  type         = "PATH"
  compare_type = "STARTS_WITH"
  value        = "{{ $r.Path }}"
}
{{- end }}

{{- if $.CreateTLS }}
resource "openstack_lb_l7rule_v2" "https_rule_path_{{ $r.PoolName }}_{{ $i }}" {
  l7policy_id  = "${openstack_lb_l7policy_v2.https_{{ $r.PoolName }}_{{ $i }}.id}"
  type         = "PATH"
  compare_type = "STARTS_WITH"
  value        = "{{ $r.Path }}"
}
{{- end }}
{{- end }}

{{- if ne $r.Host "" }}
{{- if ne $.SkipHTTP true }}
resource "openstack_lb_l7rule_v2" "http_rule_host_{{ $r.PoolName }}_{{ $i }}" {
  l7policy_id  = "${openstack_lb_l7policy_v2.http_{{ $r.PoolName }}_{{ $i }}.id}"
  type         = "HOST_NAME"
  compare_type = "EQUAL_TO"
  value        = "{{ $r.Host }}"
}
{{- end }}

{{- if $.CreateTLS }}
resource "openstack_lb_l7rule_v2" "https_rule_host_{{ $r.PoolName }}_{{ $i }}" {
  l7policy_id  = "${openstack_lb_l7policy_v2.https_{{ $r.PoolName }}_{{ $i }}.id}"
  type         = "HOST_NAME"
  compare_type = "EQUAL_TO"
  value        = "{{ $r.Host }}"
}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{- if and ($.ManageSecurityGroups) ($.Pools) }}
locals {
  port_ids = "${distinct(concat(
{{- range $p := $.Pools }}
{{- range $m := $p.Members }}
data.openstack_networking_port_ids_v2.server_ports_{{ $p.Name }}_{{ $m.Name }}.ids,
{{- end }}
{{- end }}
))}"
  sg_ids = "${list(
{{- range $i, $p := $.Pools }}
openstack_networking_secgroup_v2.sg_pool_{{ $p.Name }}.id,
{{- end }}
)}"
}

# TODO: port IDs sorting
resource "openstack_networking_port_secgroup_associate_v2" "servers_port_sgs_{{ $.LoadBalancerUID }}" {
  count = "${length(local.port_ids)}"

  port_id = "${local.port_ids[count.index]}"
  security_group_ids = "${local.sg_ids}"
}
{{- end }}

output "lb_ip" {
{{- if $.IsInternal }}
  value = "${openstack_lb_loadbalancer_v2.{{ $.LoadBalancerUID }}.vip_address}"
{{- else }}
  value = "${openstack_networking_floatingip_v2.{{ $.LoadBalancerUID }}_fip.address}"
{{- end }}
}
`
