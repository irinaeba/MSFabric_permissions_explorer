# Fabric Permissions Explorer

Local web application for auditing direct Microsoft Fabric item access and validating two distinct data paths:

- Fabric SQL analytics endpoint access
- Direct OneLake ABFS access

The app lets an administrator select a workspace and Microsoft Entra user or service principal, identify Lakehouses and Warehouses with direct access, then validate SQL endpoint or OneLake storage access.

## Walkthrough

<video src="images/Fabric_permissions_recording.mov" controls muted playsinline width="100%"></video>

If the video does not render in your GitHub client, [open the walkthrough recording](images/Fabric_permissions_recording.mov).

## Features

- Audits direct item access through the Fabric Admin `List Access Entities` preview API.
- Shows all Admin-visible Lakehouses and Warehouses in a workspace.
- Highlights direct-access items in green and unavailable items in grey.
- Connects to mapped SQL endpoints with the test service principal.
- Lists SQL metadata and runs one read-only `SELECT` query.
- Lists OneLake ABFS table paths and previews an accessible Parquet file.

## Prerequisites And Setup

Follow the [setup guide](SETUP_GUIDE.md) before running the application. It covers:

- Test and Admin service principal API permissions
- Least-privilege direct item access
- OneLake security roles for ABFS validation
- SQL table, row-level, and column-level security

## Configuration

Copy `.env.example` to `.env` and provide credentials for both service principals:

```text
TENANT_ID=your-tenant-id

SP_TEST_CLIENT_ID=your-test-service-principal-client-id
SP_TEST_CLIENT_SECRET=your-test-service-principal-secret
SP_TEST_DISPLAY_NAME=your-test-service-principal-display-name

SP_ADMIN_CLIENT_ID=your-admin-service-principal-client-id
SP_ADMIN_CLIENT_SECRET=your-admin-service-principal-secret
```

Create `config/sql_endpoints.json` from `config/sql_endpoints.example.json` for items that should open directly on the SQL tab.

```json
{
  "Lakehouse_Name": "endpoint-id.datawarehouse.fabric.microsoft.com",
  "Warehouse_Name": "endpoint-id.datawarehouse.fabric.microsoft.com"
}
```

Do not commit `.env` or `config/sql_endpoints.json`.

## Run Locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open the local URL reported by Flask, normally `http://127.0.0.1:5000`.

## Notes

- SQL endpoint, OneLake ABFS, and direct item access are separate Fabric permission layers.
- The direct-access audit uses Fabric Admin preview APIs, which can change and have service limits.
- Fabric currently does not expose a supported public write API for granting or revoking Lakehouse/Warehouse item Direct access.
