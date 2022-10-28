# Validation Rules

Validation rules let you configure how to manage vulnerabilities in your cluster workloads. 

kube-sentry can be configured in sentry mode, which will deny pod admittance into the cluster via sending back a validation failure to the API server.

If sentry mode is disabled, validation will succeed and the pod will be allowed admittance into the cluster regardless of scan results. 

These rules are configured in the helm values and supplied to the program via its arguments. 

```yaml
image:
  args:
    ...
    sentryMode: "true"
    forbiddenCves: "CVE-2020-36309, CVE-2013-0337"
    numCriticalCves: "10"
    numAllowedCves: "10"
```

### Forbidden CVEs
This rule allows you to specify which CVE's will cause an automatic validation failure if found in any of the pod's container images.

### Number of Critical CVEs
If the total number of Critical CVE's (summed from all pod container images) exceeds this value, validation will fail. 

### Number of Allowed CVEs
If the total number of CVE's (summed from all pod container images) exceeds this value, validation will fail. 