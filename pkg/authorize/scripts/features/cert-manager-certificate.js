//
// Description: this authorizer is responsible for checking the cert-manager Certificate type for internal dns
// request does not cross over a namespace boundary
//

var apiGroup = "certmanager.k8s.io/v1alpha1";
var apiKind = "Certificate";
var issuer = "platform-ca";
var issuerType = "ClusterIssuer";

// isFiltered checks the resource is of interest
function isFiltered(o) {
  if (o.apiVersion != apiGroup) {
    return false;
  }
  if (o.kind != apiKind) {
    return false;
  }
  if (o.spec.issuerRef.kind != issuerType) {
    return false;
  }
  if (o.spec.issuerRef.name != issuer) {
    return false;
  }

  return true
}

// validHostname checks the hostname comforms to what is permitted
function validHostname(hostname) {
  var namespace = object.metadata.namespace;
  var filter = new RegExp("^([a-zA-Z0-9_]*|([0-9]{1,3}\.){3}[0-9]{1,3}|[a-zA-Z0-9_]*\."+namespace+"\.svc\.cluster\.local)$");
  if (filter.exec(hostname)) {
    return true;
  }

  return false
}

// validate is responsible checking the resource
function validate(o) {
  if (o.spec["commonName"] != "") {
    //console.log(JSON.stringify(o))
    var cn = o.spec["commonName"];
    if (validHostname(cn) == false) {
      deny("spec.commonName", "certificate common name: "+cn+" does not comply with cluster policy", cn);
      return;
    }
    if (o.spec["dnsNames"]) {
      for (var i = 0; i < o.spec["dnsNames"].length; i++) {
        cn = o.spec["dnsNames"][i]
        if (validHostname(cn) == false) {
          deny("spec.dnsNames["+i+"]", cn+" is denied by cluster policy, being outside your namespace", cn)
          return
        }
      }
    }
  }
}

if (isFiltered(object)) {
  validate(object)
}
