# Task 1: Configure a Pod with Security Context

## Description

In this task, you will create a Pod with a security context that runs as a non-root user and prevents privilege escalation.

## Background

Security Contexts in Kubernetes allow you to set specific security-related settings for Pods and containers. This includes:

- User and group IDs
- Running as non-root
- Preventing privilege escalation
- Adding or dropping Linux capabilities

## Objectives

1. Create a Pod named `secure-pod` in the `default` namespace
2. Configure the Pod to run as a non-root user (user ID 1000)
3. Prevent privilege escalation
4. Verify the security settings are applied correctly

## Step-by-Step Guide

1. Create a YAML file for the secure Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: default
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
  containers:
  - name: nginx
    image: nginx:1.20
    securityContext:
      allowPrivilegeEscalation: false
    ports:
    - containerPort: 80
```
2. Apply the YAML to create the Pod:
```
kubectl apply -f secure-pod.yaml
```
3. Verify the Pod is running:
```
kubectl get pod secure-pod
```
4. Check the security context of the running Pod:
```
kubectl get pod secure-pod -o yaml | grep -A 10 securityContext
```

## Hints
<details>
Hint 1: Security Context Levels
</details>
<summary>
Remember that security contexts can be applied at both the Pod level and at the container level. Pod-level settings apply to all containers, while container-level settings override Pod-level settings.
</summary>

<details>
Hint 2: Checking User ID
</details>
<summary>
You can verify the user ID by executing a command in the container:
```bash
kubectl exec secure-pod -- id
```
</summary>

## Validation Criteria

Pod secure-pod exists in the default namespace
Pod is running with user ID 1000
Pod has privilege escalation disabled
Pod status is Running