var imageFilter = /^.*cfssl-sidekick:v.*/;
var bundleName = "bundle";
var bundlePath = "/etc/ssl/certs";

// checkDeployment checks if the object is being filtered by us
function checkDeployment(o) {
  if (o.kind != "Deployment") {
    return;
  }
  validateContainers("spec.initContainers", o.spec.template.spec.initContainers, o.spec.template.spec.volumes);
  validateContainers("spec.containers", o.spec.template.spec.containers, o.spec.template.spec.volumes);
}

function hasBundleVolume(list) {
  for (var i = 0; i < list.length; i++) {
    if (list[i].configMap) {
      if (list[i].configMap.name == bundleName) {
        return list[i].name;
      }
    }
  }

  return "";
}

function hasVolumeMount(name, list) {
  for (var i = 0; i < list.length; i++) {
    if (list[i].name != name) {
      continue;
    }
    if (list[i].name == bundleName) {
      return true;
    }
  }

  return false;
}

// validateContainers checks the containers is fine
function validateContainers(path, list, volumes) {
  if (list === null || list.length <= 0) {
    return;
  }
  for (var i = 0; i < list.length; i++) {
    //console.log(JSON.stringify(list[i], null, 2));
    // @step: check the list is using the image
    if (!imageFilter.exec(list[i].image)) {
      continue;
    }
    var volumeName = hasBundleVolume(volumes);
    if (volumeName == "") {
      deny(path, "the deployment requires the bundle volume mounted", "");
      return;
    }

    // @step: check the container has the volume mounted
    if (!hasVolumeMount(volumeName, list[i].volumeMounts)) {
      deny(path + "[" + i + "].volumeMounts", "cfssl-sidekick container needs to mount configmap: " + volumeName + " in " + bundlePath , "");
    }
  }

  return;
}

checkDeployment(object);

