Output demo.mp4
Output demo.gif

Set FontSize 20
Set Width 1200
Set Height 600

Type "cd /Users/tks/Projects/kube-sentry/deploy/kube-sentry"
Enter

Sleep 1s
Type "ls"
Enter
Sleep 1s

Space
Type "helm install kube-sentry -n kube-sentry . --wait"
Enter
Sleep 20s

Space
Type "clear"
Enter
Sleep 1s

Type "kubectl get pods -n kube-sentry"
Enter
Sleep 5s

Space
Type "kubectl apply -f https://k8s.io/examples/pods/simple-pod.yaml -n kube-sentry"
Enter
Sleep 10s
