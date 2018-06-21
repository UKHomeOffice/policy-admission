
## **Kubernetes Policy Admission Controller**

The [policy-admission](https://github.com/UKHomeOffice/policy-admission) is a [custom admission controller](https://kubernetes.io/docs/admin/extensible-admission-controllers/) used to enforce a collection of security and administrative policies across our kubernetes clusters. Each of the authorizers (https://github.com/UKHomeOffice/policy-admission/tree/master/pkg/authorize) are enabled individually via the command option --authorizer=NAME:CONFIG_PATH (note if no configuration path is given we use the default configuration for that authorizer).

```shell
$ bin/policy-admission --help
NAME:
   policy-admission - is a service used to enforce security policy within a cluster

USAGE:
    [global options] command [command options] [arguments...]

VERSION:
   v0.0.18 (git+sha: 83e2063)

AUTHOR:
   Rohith Jayawardene <gambol99@gmail.com>

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --listen INTERFACE     network interface the service should listen on INTERFACE (default: ":8443") [$LISTEN]
   --tls-cert PATH        path to a file containing the tls certificate PATH [$TLS_CERT]
   --tls-key PATH         path to a file containing the tls key PATH [$TLS_KEY]
   --authorizer value     enable an admission authorizer, the format is name=config_path (i.e images=config.yaml)
   --cluster NAME         the name of the kubernetes cluster we are running NAME [$KUBE_CLUSTER]
   --namespace NAME       namespace to create denial events (optional as we can try and discover) NAME (default: "kube-admission") [$KUBE_NAMESPACE]
   --slack-webhook value  the slack webhook to send the events to [$SLACK_WEBHOOK]
   --enable-logging BOOL  indicates you wish to log the admission requests for debugging BOOL [$ENABLE_LOGGING]
   --enable-metrics BOOL  indicates you wish to expose the prometheus metrics BOOL [$ENABLE_METRICS]
   --enable-events BOOL   indicates you wish to log kubernetes events on denials BOOL [$ENABLE_EVENTS]
   --rate-limit DURATION  the time duration to attempt to wrap up duplicate events DURATION (default: 1m0s) [$RATE_LIMIT]
   --verbose BOOL         indicates you wish for verbose logging BOOL [$VERBOSE]
   --help, -h             show help
   --version, -v          print the version
```

Note, the configuration is auto-reloaded, so you can chunk the configuration files in the [configmap](https://kubernetes.io/docs/tasks/configure-pod-container/configmap/) and on changes the authorizer will automatically pick on the changes.

### **Prometheus Metrics**
The admission controller on `/metrics` on the listening port produce a series of metrics related to request approvals and denial and a breakdown of the latency per authorizer and request. The feature is enabled via `--enable-metrics` _(albeit defaulting to true)_.

### **Slack Integration**

The admission controller along with creating kubernetes events in specified namespace _(via the `--enable-events` command line option)_ can also publish denial to a slack channel. Simply pass the `--slack-webhook` or inject the `SLACK_WEBHOOK` environment variable. This event will detail Kind, Name, Namespace, Username and the denial message in the event.

### **Authorizers**

An authorizer is enabled via the command line switch `--authorizer=name=config_file_path` i.e. `--authorizer=images=/config/images.yml`. The configuration as well as the defaults for all of these can be found in the `doc.go` in each of the authorizer folders. Each of the authorizer's can be configured to ignore certain namespaces.

Initially the project started off with a series of authorizer's however when the `scripts` authorizer was added _most_ of coded authorizer's could be replaced with a script.

#### **- Scripts Authorizer**

The scripts authorizer _(--authorizer=scripts=config)_ provides an embedded javascript runtime via [github.com/robertkrimen/otto](https://github.com/robertkrimen/otto). Both the object and namespace it derives is inject into the script as a javascript object. An explain before for an Ingress resource

```Javascript
function isFiltering(o) {
  if (o.kind != "Ingress") {
    return false
  }
  annotations = o.metadata.annotations
  if (annotations["ingress.kubernetes.io/class"] != "default") {
    return false
  }

  return true
}

if (isFiltering(object)) {
  // do some logic
  provider = o.metadata.annotations["ingress.kubernetes.io/provider"]
  if (provider != "http") {
    deny("metadata.annotations[ingress.kubernetes.io/provider]", "you must use a http provider", provider)
  }
}
```

You can find a few more examples in the [features folder](https://github.com/UKHomeOffice/policy-admission/tree/master/pkg/authorize/scripts/features). By default everyone is allowed, if you wish to deny and object, you can call the `deny` method, passing the field and reason for denial.

#### **- Images**

Images provides a means to control which container images are permitted to run within the environment. Applied to both the `initContainers` and `containers` of any pods which are created. The configuration for authorizer contains a series of regex's, which are taken as the default policy, however it will also read the annotation `policy-admission.acp.homeoffice.gov.uk/images` on the pod namespace; a comma separated list of regex's which can add on top of the default policies.

```YAML
apiVersion: v1
kind: Namespace
metadata:
  name: test
  annotations:
    policy-admission.acp.homeoffice.gov.uk/images: ^docker.io/ukhomehomeoffice/.*$, quay.io/ukhomehomeoffice/.*$
```

#### **- Domains**

The domains authorizer provides one a means to control which hostname's / site are permitted via ingress resources and to control those at a namespace level, ensuring pods from another namespace can't take over a URL from another hosted site. Namespaces are annotated with the `policy-admission.acp.homeoffice.gov.uk/domains` tag, which is a comma separated list of domains this namespace can create ingress resources for. This hostname's themselves may contain a single wildcard i.e. `*.example.com`

#### **- Kube Cert Manager**

This authorizer is fairly bespoke, it was added as a number of users were getting the configuration wrong and causing the [kube cert manager](https://github.com/PalmStoneGames/kube-cert-manager) to fail and hit Letsencrypt limits. The authorizer performs a series of checks against a ingress resource which has been labelled to consume certificates from Letencrypt. This is broken down depending on internal or external ingress ELB's.

For internal:
- we ensure it's not trying to use HTTP as the challenge and has selected dns.
- we ensure the domain name is hosted by us and thus kube-cert-manager can add the TXT record.

For External:
- we ensure the ingress is not attached to an internal ELB.
- we ensure the resource if using DNS the zone is hosted by us.
- we ensure if it's using HTTP that the hostname is a CNAME to our ingress ELB.

#### **- Services**

Services provides a means to control the kubernetes service types a namespace can use. In general we don't want anyone to be able to open `NodePorts` or `LoadBalancer` services. The authorizer takes the default configuration which is `ClusterIP` only and also reads the `policy-admission.acp.homeoffice.gov.uk/services` annotation from the namespace to see if anything else is permitted.

#### **- Values**

The values is generic authorizer used to match one or more attributes targeted via jsonpath and regex the values against a regexp. It can be used to enforce certain labels or annotation's i.e. a namespace must have a contact label etc. The configuration is as below

```YAML
filter-on: Ingress
matches:
- path: metadata.annotations
  key-filter: ingress.kubernetes.io/provider
  value: ^http$
## OR on a namespace
filter-on: Namespace
matches:
- path: metadata.annotations
  key-filter: maintainers
  value: ^.*$
  required: true
```
#### **- Toleration's & Taints**

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

An example configuration is;

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

