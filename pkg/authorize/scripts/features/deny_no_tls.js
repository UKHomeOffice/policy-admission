
var tlsEnabled = "ingress.kubernetes.io/secure-backends";

function isFiltered(o) {
  if (o.kind != "Ingress") {
    return false;
  }

  return true;
}

function isValid(o) {
  annotations = o.metadata.annotations;
  if (annotations[tlsEnabled] == "" || annotations[tlsEnabled] != "true" ) {
    deny("metadata.annotations["+tlsEnabled+"]", "you must use a secure backend and have tls enabled");
  }
}

if (isFiltered(object)) {
  isValid(object);
}
