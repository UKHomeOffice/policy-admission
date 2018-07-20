//
// Description: the authorizer is responsible for checking that ingresses which are using the DNS challenge
// with cert-manager are within a permitted list.
//

var acmeEnabled = "certmanager.k8s.io/enabled";
var acmeChallenge = "certmanager.k8s.io/acme-challenge-type";
var domains = [
  "*.example.com"
];

// isFiltered checks if the ingress resource is
function isFiltered(o) {
  if (o.kind != "Ingress") {
    return false;
  }
  annotations = o.metadata.annotations;
  if (annotations[acmeEnabled] != "true") {
    return false;
  }
  if (o.spec.rules.length <= 0) {
    return false
  }

  return true;
}

// validation is responsible validating the ingress resource
function validate(o) {
  annotations = o.metadata.annotations;
  if (annotations[acmeChallenge] == "dns01") {
    for (var j = 0; j < o.spec.rules.length; j++) {
      x = o.spec.rules[j];
      if (["host"] == "") {
        deny("spec.rules["+j+"].host", "the hostname is not set", "");
        return;
      }
      // console.log("rules: " + JSON.stringify(x))
      var found = false;
      for (var i = 0; i <= domains.length; i++) {
        if (inDomain(x["host"], domains[i]) === true) {
          found = true;
          break;
        }
      }
      if (found == false) {
        deny("spec.rules["+j+"].host", "the hostname is not permitted by policy", x["host"]);
        return;
      }
    }
  }
}

if (isFiltered(object)) {
  validate(object)
}
