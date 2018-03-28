## **Policy Enforcement**

The [policy-admission](https://github.com/UKHomeOffice/policy-admission) is a [custom admission controller](https://kubernetes.io/docs/admin/extensible-admission-controllers/) used to enforce a collection of security and administrative policies across our kubernetes clusters. Each of the authorizrs (https://github.com/UKHomeOffice/policy-admission/tree/master/pkg/authorize) are enabled individually via the command option --authorizer=NAME:CONFIG_PATH (note if no configuration path is given we use the default configuration for that authorizer).

```shell
[jest@starfury policy-admission]$ bin/policy-admission help
NAME:
   policy-admission - is a service used to enforce security policy within a cluster

USAGE:
    [global options] command [command options] [arguments...]

VERSION:
   v0.0.13 (git+sha: 01de112)

AUTHOR:
   Rohith Jayawardene <gambol99@gmail.com>

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --listen INTERFACE     network interface the service should listen on INTERFACE (default: ":8443") [$LISTEN]
   --tls-cert PATH        path to a file containing the tls certificate PATH [$TLS_CERT]
   --tls-key PATH         path to a file containing the tls key PATH [$TLS_KEY]
   --authorizer value     enable an admission authorizer, the format is name=config_path (i.e securitycontext=config.yaml)
   --namespace NAME       namespace to create denial events (optional as we can try and discover) NAME (default: "kube-admission") [$KUBE_NAMESPACE]
   --enable-logging BOOL  indicates you wish to log the admission requests for debugging BOOL [$ENABLE_LOGGING]
   --enable-metrics BOOL  indicates you wish to expose the prometheus metrics BOOL [$ENABLE_METRICS]
   --enable-events BOOL   indicates you wish to log kubernetes events on denials BOOL [$ENABLE_EVENTS]
   --help, -h             show help
   --version, -v          print the version
```

Note, the configuration is auto-reloaded, so you can chunk the configuration files in the [configmap](https://kubernetes.io/docs/tasks/configure-pod-container/configmap/) and on changes the authorizer will automatically pick on the changes.

#### **Ingress Domains**

-----------
Ingress-admission is a [external admissions controller](https://kubernetes.io/docs/admin/extensible-admission-controllers/) used to control the domains which a namespace can request. At present in a multi-tenanted environment the default [ingress controller](https://github.com/kubernetes/ingress) for kubernetes doesn't provide any control as to which domains a ingress resource can use; meaning anyone can capture traffic from any domains / paths. Given the namespace is the one element we have complete control over *(for us anyhow)*, the admission controller uses this as a reference point for control.

The annotation *"ingress-admission.acp.homeoffice.gov.uk/domains"* applied to the namespace is used to control which domains the namespace is permitted to request. The value is a comma separated list of domains;

```shell
$ kubectl annotate namespace \
mynamespace ingress-admission.acp.homeoffice.gov.uk/domains="hostname.domain.com,*.wild.domain.com"
```

#### **Pod Security Policies / Security Context**

Due to an issue in the current code base whereby if a user has RBAC access to multiple policies a random one will be chosen those authorizer reuses the kubernetes codebase but fixes the issue. The configuration for the authorizer is;

```go
// Config the security policies configuration
type Config struct {
	// Defaul is the name of the default policy to user
	Default string `yaml:"default"`
	// IgnoreNamespaces is a collection of namespace to bypass enforcement
	IgnoreNamespaces []string `yaml:"ignored-namespaces"`
	// Policies is a list of pod security policies which are available
	Policies map[string]extensions.PodSecurityPolicySpec `yaml:"policies"`
	// NamespaceMapping is a predefined list of namespace to policy mapping
	NamespaceMapping map[string]string `yaml:"namespace-mapping"`
}
```

An example of a default and privileged policy can be found [here](https://github.com/UKHomeOffice/policy-admission/blob/master/pkg/authorize/securitycontext/config_test.yml).

Note, unlike in the kubernetes PSP the selection is performed via RBAC in this authorizer you have a default policy, a predefined mapping for namespace if specified and you can also use namespace annotation to selectively choose the policy.

```YAML
apiVersion: v1
kind: Namespace
metadata:
  name: test
  annotations:
    policy-admission.acp.homeoffice.gov.uk/securitycontext: privileged
```

The authorizer reuses the kubernetes codebase to validate the pod security policy.

#### **Images**

This is authorizer providers a mechanism to control which docker repositories pods are permitted to reference. Again the formula is similar to the rest where by you have a default policy defined in the configuration and then permitted to customize at a namespace level via annotation.


Using the annotation.

```YAML
apiVersion: v1
kind: Namespace
metadata:
  name: test
  annotations:
    policy-admission.acp.homeoffice.gov.uk/images: ^docker.io/ukhomehomeoffice/.*$, quay.io/ukhomehomeoffice/.*$
```

#### **Tolerations & Taints**

The current pod tolerations admission gave more headache then features so we combined the enforcement into an authorizer. The behaviors is as such.

* Check the pod tolerations against the default whitelist defined in the configuration.
* If an annotation exists on the namespace, check the pod against the whitelist

The configuration for the authorizer is

```go
// Config is the configuration for the taint authorizer
type Config struct {
	// IgnoreNamespaces is list of namespace to
	IgnoreNamespaces []string `yaml:"ignored-namespaces" json:"ignored-namespaces"`
	// DefaultWhitelist is default whitelist applied to all unless a namespace has one
	DefaultWhitelist []core.Toleration `yaml:"default-whitelist" json:"default-whitelist"`
}
```

An example config is;

```YAML
ignored-namespaces:
- kube-admission
- kube-system
- logging
- sysdig-agent
default-whitelist:
- key: node.alpha.kubernetes.io/notReady
  operator: '*'
  value: '*'
  effect: '*'
- key: node.alpha.kubernetes.io/unreachable
  operator: '*'
  value: '*'
  effect: '*'
- key: dedicated
  operator: '*'
  value: backend
  effect: '*'
- key: dedicated
  operator: '*'
  value: liberal
  effect: '*'
- key: dedicated
  operator: '*'
  value: strict
  effect: '*'
```

For the namespace whitelist annotation the tolerations must be specified in json for:

```YAML
apiVersion: v1
kind: Namespace
metadata:
  name: test
  annotations:
    policy-admission.acp.homeoffice.gov.uk/tolerations: |
      [
        {
          "key": "dedicated",
          "operator": "*",
          "value": "compute",
          "effect": "*"
        },
        {
          "key": "dedicated",
          "operator": "*",
          "value": "liberal",
          "effect": "*"
        },
        {
          "key": "dedicated",
          "operator": "*",
          "value": "strict",
          "effect": "*"
        }
      ]
```
