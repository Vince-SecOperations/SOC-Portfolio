# Case 11: Cloud Forensics – GCP Credential Breach

## Overview

This investigation focuses on analyzing a potential credential breach within a Google Cloud Platform (GCP) environment. Using cloud audit logs and the `jq` JSON parser, we track the attacker's actions, including access to storage buckets, Compute Engine instances, and Cloud SQL databases.

## Objectives

1. Identify the compromised user account.
2. Determine the first Google Cloud Storage bucket accessed by the attacker.
3. Identify objects potentially exfiltrated.
4. Track Compute Engine instance access.
5. Determine service accounts used for API interactions.
6. Trace attempted Cloud SQL database exfiltration.
7. Identify newly created service accounts and secret keys.

## Methodology

* Use `jq` to parse JSON logs (`logs.json`) exported from GCP.
* Filter by `principalEmail`, `resourceName`, `methodName`, and `serviceAccountDelegationInfo`.
* Cross-reference API actions to identify exfiltration attempts and persistence mechanisms.

## Analysis & Findings

### Q1: Compromised User Account

* **Command:** `jq '.[] | .protoPayload.authenticationInfo.principalEmail' logs.json | sort | uniq -c | sort -nr`
* **Compromised User:** `david.smith8392173781@gmail.com`
<img width="1626" height="860" alt="image" src="https://github.com/user-attachments/assets/7ba4d785-de8f-44e8-91ca-f6371a9b8fed" />

### Q2: First Accessed GCS Bucket

* **Command:** `jq '.[] | select(.protoPayload.resourceName != null and (.protoPayload.resourceName | contains("buckets"))) | {bucket: .protoPayload.resourceName, user: .protoPayload.authenticationInfo.principalEmail}' logs.json`
* **Bucket:** `projects/_buckets/confidential-documents-482374561`
<img width="2154" height="1212" alt="image" src="https://github.com/user-attachments/assets/d48a6efa-04a3-4ebc-afbe-b5617c26f6ba" />

### Q3: Object Potentially Exfiltrated

* **Command:** `jq '.[] | select(.protoPayload.resourceName != null and (.protoPayload.resourceName | test("/buckets/confidential-documents-482374561/"))) | {bucket: (.protoPayload.resourceName | split("/")[3]), object: .protoPayload.resourceName}' logs.json`
* **Object:** `[Object Name Placeholder]`
<img width="1548" height="660" alt="image" src="https://github.com/user-attachments/assets/5b6d7c92-8667-4384-890d-f8d0b6d2a666" />

### Q4: Compute Engine Instance Accessed

* **Command:** `jq '.[] | select(.protoPayload.authenticationInfo.principalEmail == "david.smith8392173781@gmail.com" and .protoPayload.serviceName == "compute.googleapis.com" and .protoPayload.authorizationInfo[].resource? != null and (.protoPayload.authorizationInfo[].resource | contains("/instances/"))) | .protoPayload.authorizationInfo[].resource' logs.json`
* **Instance:** `[Compute Instance Name Placeholder]`
<img width="1586" height="1038" alt="image" src="https://github.com/user-attachments/assets/57f45241-8006-4dd2-a884-89d85290f822" />

### Q5: Service Account Used

* **Command:** `jq '.[] | select(.protoPayload.authenticationInfo.serviceAccountDelegationInfo != null) | {instance: .protoPayload.resourceName, serviceAccount: .protoPayload.authenticationInfo.principalEmail}' logs.json`
* **Service Account:** `cloudops-service@hybrid-elixir-370815.iam.gserviceaccount.com`
<img width="2078" height="1328" alt="image" src="https://github.com/user-attachments/assets/a98b8273-05ab-4da5-993e-71d49180143a" />

### Q6: Cloud SQL Database Targeted

* **Command:** `jq '.[] | select(.protoPayload.authenticationInfo.principalEmail == "david.smith8392173781@gmail.com" and .protoPayload.serviceName == "cloudsql.googleapis.com") | {database: .protoPayload.resourceName, user: .protoPayload.authenticationInfo.principalEmail}' logs.json`
* **Database:** `[Cloud SQL Database Name Placeholder]`
<img width="2784" height="706" alt="image" src="https://github.com/user-attachments/assets/74dc7085-49ac-4eb5-af52-5160893eb618" />

### Q7: Bucket Target for SQL Export

* **Command:** `jq '.[] | select(.protoPayload.resourceName != null and (.protoPayload.resourceName | contains("analytics-db")) and (.protoPayload.authorizationInfo[].permission == "cloudsql.instances.export")) | {uri: .protoPayload.resourceName, message: .protoPayload.status.message}' logs.json`
* **Bucket:** `[Export Bucket Name Placeholder]`
<img width="2780" height="628" alt="image" src="https://github.com/user-attachments/assets/1db13ee8-acdf-4f23-a541-1676541e2c2e" />

### Q8: Newly Created Service Account

* **Command:** `jq '.[] | select(.protoPayload.methodName == "google.iam.admin.v1.CreateServiceAccount") | {createdBy: .protoPayload.authenticationInfo.principalEmail, serviceAccountId: .protoPayload.request.account_id}' logs.json`
* **Service Account ID:** `cloud-ops-service`
<img width="1980" height="576" alt="image" src="https://github.com/user-attachments/assets/dc16ac4d-90dd-49ac-b08d-cc60f1025373" />

### Q9: Secret Key Generated

* **Command:** `jq '.[] | select(.protoPayload.methodName == "google.iam.admin.v1.CreateServiceAccountKey") | {createdBy: .protoPayload.authenticationInfo.principalEmail, serviceAccountId: .protoPayload.response.name}' logs.json`
* **Secret Key ID:** `[Secret Key ID Placeholder]`
<img width="2102" height="434" alt="image" src="https://github.com/user-attachments/assets/bb305699-0fc1-49be-b459-70f463eb8253" />

## Artifacts

* `logs.json`
* `extracted-data.csv` (parsed outputs of interest)

## Queries

* Stored in `queries/` folder, one file per question for reproducibility.
