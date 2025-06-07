# Task 2: Monitor and Detect Suspicious Activities

## Description

In this task, you will monitor Falco logs to detect the suspicious activities triggered by the test deployments and identify which pods are performing unauthorized actions.

## Background

The test deployments include:
- An `httpd` container that modifies `/etc/passwd` (unauthorized file modification)
- An `nginx` container that runs package management commands (unauthorized process execution)

These activities should trigger your custom Falco rules and generate security alerts.

## Objectives

1. Monitor Falco logs in real-time
2. Identify the pod running httpd that modifies `/etc/passwd`
3. Identify the pod running nginx that triggers package management alerts
4. Scale down the httpd deployment to stop the suspicious activity

## Step-by-Step Guide

1. **Start monitoring Falco logs in real-time:**

```bash
# Monitor Falco logs (run this in a separate terminal)
sudo journalctl -u falco -f
```

2. **Wait and observe the alerts:**

The pods should trigger the following alerts:
- "Passwd file modified" from the httpd container
- "Package management process launched" from the nginx container

3. **Identify the suspicious httpd pod:**

```bash
# Find the pod running httpd image
kubectl get pods -n falco-test -o wide

# Check the pod details
kubectl describe pod -l app=suspicious-httpd -n falco-test
```

4. **Scale down the httpd deployment:**

```bash
# Scale the suspicious httpd deployment to 0
kubectl scale deployment suspicious-httpd --replicas=0 -n falco-test

# Verify the deployment is scaled down
kubectl get deployment suspicious-httpd -n falco-test
```

5. **Verify the pod is terminated:**

```bash
# Check that the httpd pod is no longer running
kubectl get pods -n falco-test
```

## Hints

<details>
<summary>Hint 1: Reading Falco Logs</summary>
Falco logs include:
- Timestamp
- Rule name that was triggered
- Container information (ID, name, image)
- Process details
- File paths accessed
</details>

<details>
<summary>Hint 2: Correlating Alerts to Pods</summary>
Match the container name in Falco alerts with the pod names from `kubectl get pods`.
</details>

## Validation Criteria

- Falco detected passwd file modification from httpd container
- Suspicious httpd deployment is scaled down to 0 replicas
- Httpd pod is no longer running
- Nginx pod is still running and will be handled in the next task