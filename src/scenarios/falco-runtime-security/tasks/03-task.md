# Task 3: Customize Falco Output and Collect Logs

## Description

In this task, you will modify the Falco rule output format to include only specific fields, then collect logs for analysis. You'll focus on the nginx container that triggers package management alerts.

## Background

Falco output can be customized to include only the information you need for security analysis. This helps reduce noise and focus on relevant security data.

## Objectives

1. Find the pod running nginx that triggers package management alerts
2. Modify the Falco rule to include only: time-with-nanoseconds, container-id, container-name, user-name
3. Collect Falco logs for at least 20 seconds
4. Save the logs to `/opt/course/2/falco.log`
5. Scale down the nginx deployment

## Step-by-Step Guide

1. **Create the target directory:**

```bash
# Create directory for log collection
sudo mkdir -p /opt/course/2
```

2. **Identify the nginx pod triggering package management:**

```bash
# Find the nginx pod
kubectl get pods -n falco-test -l app=suspicious-nginx

# Monitor current Falco logs to see the nginx alerts
sudo journalctl -u falco -f | grep -i "package management"
```

3. **Modify the Falco rule output format:**

```bash
# Edit the custom rules file
sudo nano /etc/falco/rules.d/falco_custom.yaml
```

Change the "Package management process launched" rule output to:
```yaml
output: >
  Package management process launched (%evt.time container_id=%container.id container_name=%container.name user_name=%user.name)
```

4. **Restart Falco to apply the changes:**

```bash
# Restart Falco service
sudo systemctl restart falco

# Verify Falco restarted successfully
sudo systemctl status falco
```

5. **Collect logs for 20+ seconds:**

```bash
# Start collecting logs (let it run for at least 20 seconds)
sudo journalctl -u falco -f > /opt/course/2/falco.log &

# Wait for at least 20 seconds to collect logs
sleep 25

# Stop the log collection
sudo pkill -f "journalctl -u falco -f"
```

6. **Verify the log format and content:**

```bash
# Check the collected logs
sudo cat /opt/course/2/falco.log | grep -i "package management"
```

7. **Scale down the nginx deployment:**

```bash
# Scale the suspicious nginx deployment to 0
kubectl scale deployment suspicious-nginx --replicas=0 -n falco-test

# Verify the deployment is scaled down
kubectl get deployment suspicious-nginx -n falco-test
```

## Hints

<details>
<summary>Hint 1: Falco Output Fields</summary>
Common Falco output fields:
- `%evt.time` - Event timestamp with nanoseconds
- `%container.id` - Container ID
- `%container.name` - Container name
- `%user.name` - Username
- `%proc.name` - Process name
</details>

<details>
<summary>Hint 2: Log Collection</summary>
Use `&` to run the log collection in background, then use `sleep` to wait, and `pkill` to stop it.
</details>

## Validation Criteria

- Custom Falco rule output format is modified correctly
- Logs are collected for at least 20 seconds
- Logs are saved to `/opt/course/2/falco.log`
- Log format includes only the specified fields
- Nginx deployment is scaled down to 0 replicas
- All test pods are terminated