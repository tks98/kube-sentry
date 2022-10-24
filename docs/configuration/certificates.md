# Certificate Generation and Registration 

Admission controllers intercept requests to the Kubernetes API server. They can mutate and/or validate the object before persistence to etcd. Some controllers are built directly into the Kubernetes API server binary.

To write custom controllers, one can either write and compile changes directly into the API server or utilize the AdmissionRegistration API.

Kube-Sentry utilizes the AdmissionRegistrationAPI, registering it as a Validation Admission Webhook using a ValidatingWebhookConfiguration.

Custom Admission Webhooks are required to communicate with the API server over HTTPS, so TLS certificates need to be generated and registered with the API server. This is done by generating a caBundle and defining it in the ValidationWebhookConfiguration.

Kube-Sentry can utilize Certmanager's CA injector to generate the certificates, place them in a Kubernetes secret so they can be mounted, and register them with the API server by creating a caBundle and patching the ValidationWebhookConfiguration with it. 