# Fabric Permissions Explorer

Local web application for auditing direct Microsoft Fabric item access and validating two distinct data paths:

- Fabric SQL analytics endpoint access.
- Direct OneLake ABFS access.

The app is intended for administrators who need to inspect which Lakehouses and Warehouses a selected Microsoft Entra user or service principal has direct access to in a selected Fabric workspace.

## Features

- Select a workspace available to the Admin service principal.
- Select or type a user email, user display name, or service principal name.
- Query the Fabric Admin `List Access Entities` preview API to identify direct item access.
- Show all Admin-visible Lakehouses and Warehouses in the workspace.
- Highlight direct-access items in green and unavailable items in grey.
- Connect to mapped SQL endpoints with the test service principal.
- List SQL metadata and execute a single read-only `SELECT` statement.
- List OneLake ABFS table paths and preview data from an accessible Parquet file.
- Keep workspace, identity, and item results in browser session storage until explicitly refreshed.

## Architecture

Two service principals are used:

| Identity | Purpose |
|---|---|
| Test service principal | Connects to Fabric SQL endpoints and OneLake ABFS as the identity being validated. |
| Admin service principal | Lists workspaces, resolves Entra identities, and calls Fabric Admin access-audit APIs. |

The app does not expose client secrets, access tokens, Entra IDs, workspace IDs, or artifact IDs in the UI. GUID-like values in API errors are redacted before display.

## Prerequisites

- Python 3.11 or later.
- Microsoft ODBC Driver 18 for SQL Server.
- A Fabric tenant that allows service principals to use Fabric APIs.
- An Admin service principal authorized for Fabric Admin APIs and Microsoft Graph directory lookup.
- A test service principal with the item and data permissions you want to validate.

## Configuration

Copy `.env.example` to `.env` and provide credentials for both service principals:

```text
TENANT_ID=your-tenant-id

# Identity tested for SQL endpoint and OneLake ABFS data access.
SP_TEST_CLIENT_ID=your-test-service-principal-client-id
SP_TEST_CLIENT_SECRET=your-test-service-principal-secret
SP_TEST_DISPLAY_NAME=your-test-service-principal-display-name

# Identity used for workspace discovery, direct-access audits, and Entra resolution.
SP_ADMIN_CLIENT_ID=your-admin-service-principal-client-id
SP_ADMIN_CLIENT_SECRET=your-admin-service-principal-secret
```

Create a local `config/sql_endpoints.json` mapping for items that should open directly on the SQL tab. Start from `config/sql_endpoints.example.json`:

```json
{
  "Lakehouse_Name": "endpoint-id.datawarehouse.fabric.microsoft.com",
  "Warehouse_Name": "endpoint-id.datawarehouse.fabric.microsoft.com"
}
```

`config/sql_endpoints.json` is intentionally ignored by Git because it can contain environment-specific endpoint hostnames. The committed `config/sql_endpoints.example.json` documents the format.

## Run Locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open the local URL reported by Flask, normally `http://127.0.0.1:5000`.

## Permission Model

Fabric has separate permission layers:

- **Direct item access**: audited through Fabric Admin `List Access Entities`.
- **Fabric SQL endpoint**: validated by connecting with the test service principal and listing SQL metadata or running a read-only query.
- **OneLake ABFS**: validated by listing selected item table paths and reading a Parquet preview with the test service principal.

An item can be directly visible while SQL or ABFS data access remains restricted. The app intentionally keeps those checks separate.

## API Notes

The app uses Fabric Admin preview APIs for direct-access auditing. Preview APIs can change and have service limits. The direct-access list is cached in the browser session until the user explicitly clicks Refresh.

Fabric currently does not expose a supported public write API for granting or revoking Lakehouse/Warehouse item Direct access. The app audits item access only. Permission automation can be added when Fabric exposes supported write endpoints.

## Security

- Never commit `.env`.
- Never commit `config/sql_endpoints.json` with real environment endpoints.
- The web UI communicates only with the local Flask backend.
- SQL execution is restricted to one read-only `SELECT` statement and returns at most 200 rows.
