# Certificate Generation and Registration 

### Admission Controllers and Webhooks
Admission controllers intercept requests to the Kubernetes API server. They can mutate and/or validate the object before persistence to etcd. Some controllers are built directly into the Kubernetes API server binary.

To write custom controllers, one can either write and compile changes directly into the API server or utilize the AdmissionRegistration API.

Kube-Sentry utilizes the AdmissionRegistrationAPI, registering it as a Validation Admission Webhook using a ValidatingWebhookConfiguration.

### Certificate Management
Custom Admission Webhooks are required to communicate with the API server over HTTPS, so TLS certificates need to be generated and registered with the API server. This is done by generating a caBundle and defining it in the [ValidationWebhookConfiguration](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#configure-admission-webhooks-on-the-fly).

Kube-Sentry can utilize Certmanager's CA injector to generate the certificates, place them in a Kubernetes secret so they can be mounted, and register them with the API server by creating a caBundle and patching the ValidationWebhookConfiguration with it.

Certificates can also be created manually, bundled into the caBundle and supplied to the ValidatingWebhookConfiguration.

Both of these methods can be configured in the helm chart values. 

```yaml
webhook:
  caBundle:
    certmanager: # certmanager's ca-injector can be used to inject the caBundle into the ValidationWebhookConfiguration https://cert-manager.io/docs/concepts/ca-injector/
      enabled: true
      secretName: kube-sentry-cert
      annotations:
        cert-manager.io/inject-ca-from: kube-sentry/kube-sentry-cert # namespace/secretName
      dnsNames:
        - kube-sentry
        - kube-sentry.kube-sentry
        - kube-sentry.kube-sentry.svc
    value: "" # if you are not using certmanager, put the PEM encoded caBundle here and set enabled to false
```