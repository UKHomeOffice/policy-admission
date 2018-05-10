
var booleanRegex = new RegExp("^(true|false)$");
var numberRegex = new RegExp("^[0-9]*$");
var trafficRegex = new RegExp("^[0-9]*[mkg]$");
var urlRegex = new RegExp("^((https?):\/\/)?([w|W]{3}\.)+[a-zA-Z0-9\-\.]{3,}\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$");

var definitions = {
  "ingress.kubernetes.io/add-base-url": urlRegex,
  "ingress.kubernetes.io/app-root": urlRegex,
  "ingress.kubernetes.io/affinity": "^cookie$",
  "ingress.kubernetes.io/auth-type": "^(basic|digest)$",
  "ingress.kubernetes.io/auth-tls-verify-depth": numberRegex,
  "ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream": booleanRegex,
  "ingress.kubernetes.io/auth-url": urlRegex,
  "ingress.kubernetes.io/base-url-scheme": "^https?$",
  "ingress.kubernetes.io/client-body-buffer-size": trafficRegex,
  "ingress.kubernetes.io/enable-cors": booleanRegex,
  "ingress.kubernetes.io/cors-max-age": numberRegex,
  "ingress.kubernetes.io/force-ssl-redirect": booleanRegex,
  "ingress.kubernetes.io/from-to-www-redirect": booleanRegex,
  "ingress.kubernetes.io/grpc-backend": booleanRegex,
  "ingress.kubernetes.io/limit-connections": numberRegex,
  "ingress.kubernetes.io/limit-rps": numberRegex,
  "ingress.kubernetes.io/permanent-redirect": urlRegex,
  "ingress.kubernetes.io/proxy-body-size": trafficRegex,
  "ingress.kubernetes.io/proxy-connect-timeout": numberRegex,
  "ingress.kubernetes.io/proxy-send-timeout": numberRegex,
  "ingress.kubernetes.io/proxy-read-timeout": numberRegex,
  "ingress.kubernetes.io/proxy-next-upstream": numberRegex,
  "ingress.kubernetes.io/proxy-next-upstream-tries": numberRegex,
  "ingress.kubernetes.io/proxy-request-buffering": numberRegex,
  "ingress.kubernetes.io/rewrite-log": urlRegex,
  "ingress.kubernetes.io/rewrite-target": urlRegex,
  "ingress.kubernetes.io/secure-backends": booleanRegex,
  "ingress.kubernetes.io/service-upstream": booleanRegex,
  "ingress.kubernetes.io/session-cookie-hash": "^(md5|sha1|index)$",
  "ingress.kubernetes.io/ssl-redirect": booleanRegex,
  "ingress.kubernetes.io/ssl-passthrough": booleanRegex,
  "ingress.kubernetes.io/upstream-max-fails": numberRegex,
  "ingress.kubernetes.io/upstream-fail-timeout": numberRegex,
  "ingress.kubernetes.io/proxy-buffering": "^(on|off)$",
  "ingress.kubernetes.io/connection-proxy-header": "^keep-alive$",
  "ingress.kubernetes.io/enable-access-log": booleanRegex
};

// isIngressValid is responisble for checking the ingress against the regex map
function isIngressValid(o) {
  annotations = o.metadata.annotations;
  Object.keys(definitions).forEach(function(key) {
    if (annotations[key]) {
      filter = definitions[key];
      if (!filter.exec(annotations[key])) {
        deny("metadata.annotations["+key+"]", "invalid user input, should match: "+ filter.toString(), annotations[key]);
      }
    }
  });
}

// isFiltered checks if the object needs to be validated
function isFiltered(o) {
  if (o.kind != "Ingress") {
    return false;
  }
  annotations = o.metadata.annotations;
  if (annotations) {
    if (annotations["kubernetes.io/ingress.class"] == "nginx-external") {
      return true;
    }
    if (annotations["kubernetes.io/ingress.class"] == "nginx-internal") {
      return true;
    }
  }

  return false;
}

if (isFiltered(object)) {
  isIngressValid(object);
}
