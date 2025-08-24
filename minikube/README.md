# Deploy cilium on a minikube cluster

## Why

Today we have a similar setup for kind but kind runs in docker so if we want to change some net configuraiton you have to change them on your machine. For example for the bandwidth manager you have to change the default qdisc.

## Run

Today is only limited to the agent binaries.

```bash
make minikube-start
# copies only agent binaries
make minikube-copy-binaries
# installs cilium with helm chart and extra Volume mounts
make minikube-install-cilium
# Destroy the cluster
make minikube-delete
```

Tested with cilium commit: a7de0143835a080750dbbde7285be37ab8599883
