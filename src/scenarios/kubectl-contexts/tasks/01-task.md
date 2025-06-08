# Task 1: Kubectl Contexts and Certificate Extraction

## Description

You have access to multiple clusters from your main terminal through kubectl contexts. Write all context names into /home/suporte/1/contexts, one per line.
From the kubeconfig extract the certificate of user restricted@infra-prod and write it decoded to /home/suporte/1/cert.

## Background

Kubectl contexts allow you to switch between different Kubernetes clusters and users. Each context contains:
- A cluster (server endpoint and certificate authority)
- A user (client certificate and key)
- A namespace (default namespace for operations)

Certificate data in kubeconfig files is typically base64-encoded and needs to be decoded for inspection.

## Objectives

1. List all available kubectl contexts and save them to a file
2. Extract and decode a specific user's certificate from the kubeconfig
3. Understand how to manipulate kubeconfig data using kubectl and standard tools
