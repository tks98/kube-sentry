# kube-sentry
kube-sentry is a Kubernetes admission controller to automate image scanning and enforcement

webhook gets api request to create pod -> check if image has already been scanned, if not, scan it -> expose scan results as prom metrics -> store scan results in redis?
