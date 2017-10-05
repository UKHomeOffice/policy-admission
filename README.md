#### **Kubernetes Ingress Admission Controller**
-----------
Ingress-admission is a [external admissions controller](https://kubernetes.io/docs/admin/extensible-admission-controllers/) used to control the domains which a namespace can request. At present in a multi-tenanted environment the default [ingress controller](https://github.com/kubernetes/ingress) for kubernetes doesn't provide any control as to which domains a ingress resource can use; meaning anyone can capture traffic from any domains / paths. Given the namespace is the one element we have complete control over *(for us anyhow)*, the admission controller uses this as a reference point for control.

##### **- Deploy admission controller**

Their are kubernetes files in the [kube/](https://github.com/UKHomeOffice/ingress-admission/tree/master/kube) folder for deployment. One annoying issue I came across was the *kube-apiserver* uses the service IP address when calling the service, thus make sure the ip address is contained in the certificate. Essentially once the [deployment.yml](https://github.com/UKHomeOffice/ingress-admission/blob/master/kube/deployment.yml), [rbac.yml](https://github.com/UKHomeOffice/ingress-admission/blob/master/kube/rbac.yml) and [service.yml](https://github.com/UKHomeOffice/ingress-admission/blob/master/kube/service.yml) has been deployed you can register the admission controller via the [registration.yml](https://github.com/UKHomeOffice/ingress-admission/blob/master/kube/registration.yml) *(obviously you will need to remove any reference to ourselves, i.e. cfssl and ca-bundle etc)*

##### **Controlling the domains**
The annotation *"ingress-admission.acp.homeoffice.gov.uk/domains"* applied to the namespace is used to control which domains the namespace is permitted to request. The value is a comma separated list of domains;

```shell
$ kubectl annotate namespace \
mynamespace ingress-admission.acp.homeoffice.gov.uk/domains="hostname.domain.com,*.wild.domain.com"
```



