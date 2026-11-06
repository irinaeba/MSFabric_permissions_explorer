"""Local-only API for validating Fabric access with a service principal."""

import io
import os
import re
import uuid
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pyarrow.parquet as pq
import pyodbc
from azure.identity import ClientSecretCredential
from azure.storage.filedatalake import DataLakeServiceClient
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory

load_dotenv()
pyodbc.pooling = False

ROOT = Path(__file__).parent
SITE = ROOT / "site"
CONFIG = ROOT / "config"
CACHE = ROOT / ".cache"
CANDIDATE_CACHE = CACHE / "item_candidates.json"
SQL_ENDPOINT_CACHE = CONFIG / "sql_endpoints.json"
SQL_DRIVER = "ODBC Driver 18 for SQL Server"
ONELAKE_HOST = "onelake.dfs.fabric.microsoft.com"
FABRIC_API = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
REQUIRED = ("TENANT_ID", "SP_TEST_CLIENT_ID", "SP_TEST_CLIENT_SECRET")
BLOCKED_SQL = re.compile(
    r"\b(insert|update|delete|merge|drop|alter|create|truncate|exec(?:ute)?|grant|revoke|deny|use)\b",
    re.IGNORECASE,
)

app = Flask(__name__, static_folder=None)


def configured(name: str) -> str:
    return os.environ.get(name, "").strip()


def missing(*names: str) -> list[str]:
    return [name for name in names if not configured(name)]


def api_error(message: str, status: int = 400):
    response = jsonify({"error": message})
    response.headers["Cache-Control"] = "no-store"
    return response, status


def api_response(payload: dict):
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response


def safe_error(error: Exception) -> str:
    """Return diagnostic text while preventing accidental connection-string disclosure."""
    text = str(error)
    for value in (configured("SP_TEST_CLIENT_SECRET"), configured("SP_TEST_CLIENT_ID"), configured("TENANT_ID")):
        if value:
            text = text.replace(value, "[redacted]")
    text = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "[redacted-id]",
        text,
    )
    return text[:1200]


def credential() -> ClientSecretCredential:
    absent = missing(*REQUIRED)
    if absent:
        raise ValueError(f"Missing required configuration: {', '.join(absent)}")
    return ClientSecretCredential(
        tenant_id=configured("TENANT_ID"),
        client_id=configured("SP_TEST_CLIENT_ID"),
        client_secret=configured("SP_TEST_CLIENT_SECRET"),
    )


def admin_credential() -> ClientSecretCredential:
    absent = missing("TENANT_ID", "SP_ADMIN_CLIENT_ID", "SP_ADMIN_CLIENT_SECRET")
    if absent:
        raise ValueError(f"Missing required admin configuration: {', '.join(absent)}")
    return ClientSecretCredential(
        tenant_id=configured("TENANT_ID"),
        client_id=configured("SP_ADMIN_CLIENT_ID"),
        client_secret=configured("SP_ADMIN_CLIENT_SECRET"),
    )


def sql_settings(server: str = "", database: str = "") -> tuple[str, str]:
    server = server.strip()
    database = database.strip()
    if not server or not database:
        raise ValueError("Provide the selected Lakehouse SQL endpoint and database.")
    if not re.fullmatch(r"[a-zA-Z0-9-]+\.datawarehouse\.fabric\.microsoft\.com", server):
        raise ValueError("Enter a Fabric SQL endpoint hostname ending in .datawarehouse.fabric.microsoft.com.")
    return server, database


def sql_connection(server: str = "", database: str = "") -> pyodbc.Connection:
    absent = missing("SP_TEST_CLIENT_ID", "SP_TEST_CLIENT_SECRET")
    if absent:
        raise ValueError(f"Missing required configuration: {', '.join(absent)}")
    server, database = sql_settings(server, database)
    if SQL_DRIVER not in pyodbc.drivers():
        raise RuntimeError(f"Missing ODBC driver: {SQL_DRIVER}")
    connection_string = (
        f"Driver={{{SQL_DRIVER}}};Server={server},1433;Database={database};"
        f"APP=FabricPermissionsSimulator-{uuid.uuid4()};"
        f"UID={configured('SP_TEST_CLIENT_ID')};PWD={configured('SP_TEST_CLIENT_SECRET')};"
        "Authentication=ActiveDirectoryServicePrincipal;Encrypt=yes;"
        "TrustServerCertificate=no;Connection Timeout=30;"
    )
    return pyodbc.connect(connection_string)


def validate_query(sql: str) -> str:
    statement = sql.strip()
    if not statement:
        raise ValueError("Enter a SQL query.")
    if not re.match(r"^select\b", statement, re.IGNORECASE):
        raise ValueError("Only a single read-only SELECT statement is allowed.")
    if BLOCKED_SQL.search(statement) or "--" in statement or "/*" in statement:
        raise ValueError("The query contains a blocked SQL keyword or comment.")
    if statement.rstrip(";").count(";"):
        raise ValueError("Only one SQL statement is allowed.")
    return statement


def fabric_get(
    path: str, query: dict[str, str] | None = None, token: str | None = None
) -> dict:
    """Call the Fabric REST API with an app-only Fabric audience token."""
    url = f"{FABRIC_API}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    token = token or credential().get_token(FABRIC_SCOPE).token
    request_object = Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(request_object, timeout=30) as response:
            import json

            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")[:600]
        raise RuntimeError(f"Fabric REST API returned HTTP {error.code}: {body}") from error
    except URLError as error:
        raise RuntimeError(f"Unable to reach the Fabric REST API: {error.reason}") from error


def token_object_id(token: str) -> str:
    """Read the Entra service principal object ID from an already-issued JWT."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["oid"]


def token_app_id(token: str) -> str:
    """Read the Entra application/client ID from an already-issued JWT."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["appid"]


def token_roles(token: str) -> list[str]:
    """Return application roles from an already-issued JWT without logging it."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("roles", [])


def graph_get(path: str, token: str) -> dict:
    request_object = Request(
        f"https://graph.microsoft.com/v1.0{path.replace(' ', '%20')}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request_object, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")[:600]
        raise RuntimeError(f"Microsoft Graph returned HTTP {error.code}: {body}") from error


def normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def configured_service_principal_app_id(name: str) -> str:
    """Find a configured client ID by its environment-variable alias."""
    target = normalized_name(name)
    for key, value in os.environ.items():
        if not value or "CLIENT_ID" not in key:
            continue
        alias = key.replace("CLIENT_ID", "").strip("_")
        normalized_alias = normalized_name(alias)
        if alias and (
            normalized_alias == target
            or normalized_alias.endswith(target)
            or target.endswith(normalized_alias)
        ):
            return value.strip()
    return ""


def configured_test_display_name() -> str:
    return configured("SP_TEST_DISPLAY_NAME") or "Test service principal"


def visible_fabric_workspaces(token: str | None = None) -> list[dict]:
    """Return every workspace and item visible through Fabric REST metadata."""
    workspaces: list[dict] = []
    continuation_token = ""
    while True:
        query = {"continuationToken": continuation_token} if continuation_token else None
        page = fabric_get("/workspaces", query, token)
        workspaces.extend(page.get("value", []))
        continuation_token = page.get("continuationToken", "")
        if not continuation_token:
            break

    inventory = []
    for workspace in workspaces:
        items: list[dict] = []
        continuation_token = ""
        while True:
            query = {"continuationToken": continuation_token} if continuation_token else None
            page = fabric_get(f"/workspaces/{workspace['id']}/items", query, token)
            items.extend(page.get("value", []))
            continuation_token = page.get("continuationToken", "")
            if not continuation_token:
                break
        inventory.append({
            "id": workspace["id"],
            "name": workspace.get("displayName", workspace["id"]),
            "items": [
                {"id": item["id"], "name": item.get("displayName", item["id"]), "type": item.get("type", "Unknown")}
                for item in items
            ],
        })
    return inventory


def load_item_candidates(admin_token: str, force_refresh: bool = False) -> tuple[list[dict], str]:
    """Load Lakehouse/Warehouse candidates once; direct access is always live."""
    if not force_refresh and CANDIDATE_CACHE.exists():
        try:
            cached = json.loads(CANDIDATE_CACHE.read_text(encoding="utf-8"))
            candidates = cached.get("items", [])
            if candidates:
                return candidates, cached.get("capturedAt", "cached inventory")
        except (json.JSONDecodeError, OSError):
            pass

    candidates = [
        {
            "workspace": workspace["name"],
            "workspaceId": workspace["id"],
            "name": item["name"],
            "itemId": item["id"],
            "type": item["type"],
        }
        for workspace in visible_fabric_workspaces(admin_token)
        for item in workspace["items"]
        if item["type"] in {"Lakehouse", "Warehouse"}
    ]
    captured_at = datetime.now(UTC).isoformat()
    CACHE.mkdir(exist_ok=True)
    CANDIDATE_CACHE.write_text(
        json.dumps({"capturedAt": captured_at, "items": candidates}),
        encoding="utf-8",
    )
    return candidates, captured_at


def configured_sql_endpoint(item_name: str) -> str:
    try:
        endpoints = json.loads(SQL_ENDPOINT_CACHE.read_text(encoding="utf-8"))
        return str(endpoints.get(item_name, "")).strip()
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return ""


@app.get("/api/status")
def status():
    sql_ready = not missing("SP_TEST_CLIENT_ID", "SP_TEST_CLIENT_SECRET")
    abfs_ready = not missing(*REQUIRED)
    fabric_ready = not missing(*REQUIRED)
    return jsonify({"sqlConfigured": sql_ready, "abfsConfigured": abfs_ready, "fabricApiConfigured": fabric_ready})


@app.get("/api/fabric/inventory")
def fabric_inventory():
    """Discover Fabric workspaces and items visible to the service principal."""
    try:
        return api_response({
            "workspaces": visible_fabric_workspaces(),
            "checkedAt": datetime.now(UTC).isoformat(),
        })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/fabric/diagnostics")
def fabric_diagnostics():
    """Return current permission-layer counts without exposing identity data."""
    try:
        token = credential().get_token(FABRIC_SCOPE).token
        inventory = visible_fabric_workspaces(token)
        lakehouses = sum(
            1 for workspace in inventory for item in workspace["items"]
            if item["type"] == "Lakehouse"
        )
        warehouses = sum(
            1 for workspace in inventory for item in workspace["items"]
            if item["type"] == "Warehouse"
        )
        return api_response({
            "checkedAt": datetime.now(UTC).isoformat(),
            "fabricRest": {
                "workspaces": len(inventory),
                "lakehouses": lakehouses,
                "warehouses": warehouses,
            },
            "configuredAbfsTarget": False,
        })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/fabric/admin-role-diagnostics")
def admin_role_diagnostics():
    """Use the configured workspace Admin to inspect direct role assignments."""
    try:
        original_token = credential().get_token(FABRIC_SCOPE).token
        original_object_id = token_object_id(original_token)
        admin_token = admin_credential().get_token(FABRIC_SCOPE).token
        admin_workspaces = fabric_get("/workspaces", token=admin_token).get("value", [])
        workspace = admin_workspaces[0] if admin_workspaces else None
        if not workspace:
            raise RuntimeError("The Admin service principal cannot find the configured workspace.")
        try:
            assignments = fabric_get(
                f"/workspaces/{workspace['id']}/roleAssignments", token=admin_token
            ).get("value", [])
        except RuntimeError as error:
            if "InsufficientWorkspaceRole" in str(error):
                return api_response({
                    "checkedAt": datetime.now(UTC).isoformat(),
                    "adminCanReadRoleAssignments": False,
                    "message": "Fabric has not authorized the Admin service principal to read workspace role assignments yet.",
                })
            raise
        original_assignments = []
        for assignment in assignments:
            principal = assignment.get("principal", {})
            if principal.get("id") == original_object_id:
                original_assignments.append(assignment.get("role", "Unknown"))
        return api_response({
            "checkedAt": datetime.now(UTC).isoformat(),
            "adminCanReadRoleAssignments": True,
            "originalServicePrincipalDirectRoles": original_assignments,
            "originalServicePrincipalHasDirectWorkspaceRole": bool(original_assignments),
        })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/setup/workspaces")
def setup_workspaces():
    """List workspaces the Admin SP can use as direct-access audit scope."""
    try:
        token = admin_credential().get_token(FABRIC_SCOPE).token
        workspaces = [
            {"id": workspace["id"], "name": workspace.get("displayName", workspace["id"])}
            for workspace in fabric_get("/workspaces", token=token).get("value", [])
        ]
        return api_response({
            "workspaces": workspaces,
            "testServicePrincipalName": configured_test_display_name(),
        })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.post("/api/setup/resolve-target")
def resolve_target():
    """Resolve a typed email or service-principal name to an Entra object ID."""
    payload = request.get_json(silent=True) or {}
    value = str(payload.get("target", "")).strip()
    if not value:
        return api_error("Enter a user email or service principal name.")
    try:
        graph_token = admin_credential().get_token(
            "https://graph.microsoft.com/.default"
        ).token
        if "@" in value:
            try:
                result = graph_get(
                    f"/users/{urlencode({'id': value})[3:]}?$select=id,displayName,userPrincipalName",
                    graph_token,
                )
            except RuntimeError as error:
                if "HTTP 404" not in str(error):
                    raise
                escaped = value.replace("'", "''")
                result = graph_get(
                    f"/users?$filter=mail eq '{escaped}' or userPrincipalName eq '{escaped}'"
                    "&$select=id,displayName,userPrincipalName,mail",
                    graph_token,
                )
                matches = result.get("value", [])
                if len(matches) != 1:
                    raise ValueError("No unique Microsoft Entra user matches that email address.")
                result = matches[0]
            return api_response({"id": result["id"], "name": result.get("displayName", value), "type": "User"})

        app_id = configured_service_principal_app_id(value)
        if app_id:
            result = graph_get(f"/servicePrincipals(appId='{app_id}')?$select=id,displayName", graph_token)
            return api_response({"id": result["id"], "name": result.get("displayName", value), "type": "ServicePrincipal"})

        escaped = value.replace("'", "''")
        user_result = graph_get(
            f"/users?$filter=displayName eq '{escaped}'&$select=id,displayName,userPrincipalName",
            graph_token,
        )
        user_matches = user_result.get("value", [])
        if len(user_matches) == 1:
            return api_response({
                "id": user_matches[0]["id"],
                "name": user_matches[0].get("displayName", value),
                "type": "User",
            })
        result = graph_get(f"/servicePrincipals?$filter=displayName eq '{escaped}'&$select=id,displayName", graph_token)
        matches = result.get("value", [])
        if len(matches) != 1:
            raise ValueError("No unique service principal matches that name.")
        return api_response({"id": matches[0]["id"], "name": matches[0].get("displayName", value), "type": "ServicePrincipal"})
    except ValueError as error:
        return api_error(str(error))
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/fabric/effective-items")
def effective_items():
    """List Lakehouses/Warehouses with a direct item permission for the test SP."""
    try:
        admin_token = admin_credential().get_token(FABRIC_SCOPE).token
        target_id = request.args.get("targetId", "").strip()
        target_type = request.args.get("targetType", "").strip()
        if not target_id:
            raise ValueError("Choose a target identity before checking direct access.")
        access_user_id = target_id
        if target_type == "ServicePrincipal":
            graph_token = admin_credential().get_token(
                "https://graph.microsoft.com/.default"
            ).token
            principal = graph_get(f"/servicePrincipals/{target_id}?$select=appId", graph_token)
            access_user_id = principal["appId"]

        entities = []
        continuation_token = ""
        while True:
            query = {"continuationToken": continuation_token} if continuation_token else None
            page = fabric_get(f"/admin/users/{access_user_id}/access", query, admin_token)
            entities.extend(page.get("accessEntities", []))
            continuation_token = page.get("continuationToken", "")
            if not continuation_token:
                break

        workspace_id = request.args.get("workspaceId", "").strip()
        all_candidates, _ = load_item_candidates(admin_token)
        workspace_candidates = {
            candidate["itemId"]: candidate
            for candidate in all_candidates
            if candidate["workspaceId"] == workspace_id
        }
        direct_access = {
            entity["id"]: {
                "permissions": details.get("permissions", []),
                "additionalPermissions": details.get("additionalPermissions", []),
            }
            for entity in entities
            if entity.get("id") in workspace_candidates
            and (details := entity.get("itemAccessDetails", {})).get("type") in {"Lakehouse", "Warehouse"}
        }
        items = [
            {
                "itemId": candidate["itemId"],
                "workspace": candidate["workspace"],
                "name": candidate["name"],
                "type": candidate["type"],
                "hasDirectAccess": candidate["itemId"] in direct_access,
                "permissions": direct_access.get(candidate["itemId"], {}).get("permissions", []),
                "additionalPermissions": direct_access.get(candidate["itemId"], {}).get("additionalPermissions", []),
                "sqlEndpoint": configured_sql_endpoint(candidate["name"]),
            }
            for candidate in workspace_candidates.values()
        ]
        items.sort(key=lambda item: (not item["hasDirectAccess"], item["type"], item["name"].lower()))
        snapshot = {
            "checkedAt": datetime.now(UTC).isoformat(),
            "checked": len(entities),
            "items": items,
            "directAccessCount": len(direct_access),
            "availableItemCount": len(items),
            "source": "Fabric Admin List Access Entities (preview)",
            "failedChecks": 0,
            "scanComplete": True,
            "workspaceId": workspace_id,
            "targetId": target_id,
        }
        return api_response(snapshot)
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/graph/admin-diagnostics")
def graph_admin_diagnostics():
    """Report whether the Admin SP currently has usable Graph application roles."""
    try:
        graph_token = admin_credential().get_token(
            "https://graph.microsoft.com/.default"
        ).token
        roles = token_roles(graph_token)
        return api_response({
            "checkedAt": datetime.now(UTC).isoformat(),
            "graphApplicationRoles": roles,
            "canInspectServicePrincipalGroupMembership": bool(
                {"GroupMember.Read.All", "Directory.Read.All"}.intersection(roles)
            ),
        })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/sql/tables")
def sql_tables():
    try:
        with sql_connection(request.args.get("server", ""), request.args.get("database", "")) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME")
            return api_response({
                "tables": [{"schema": row[0], "table": row[1]} for row in cursor.fetchall()],
            })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/sql/connection")
def sql_connection_evidence():
    """Return non-sensitive proof of the current SQL endpoint connection."""
    try:
        server = request.args.get("server", "")
        database = request.args.get("database", "")
        with sql_connection(server, database) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT DB_NAME(), SUSER_SNAME(), @@SPID")
            connected_database, sql_identity, session_id = cursor.fetchone()
            return api_response({
                "server": server,
                "requestedDatabase": database,
                "connectedDatabase": connected_database,
                "sqlIdentity": sql_identity,
                "sessionId": session_id,
            })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/sql/permissions")
def sql_permission_evidence():
    """Return effective database permissions for the connected SQL identity."""
    try:
        server = request.args.get("server", "")
        database = request.args.get("database", "")
        with sql_connection(server, database) as connection:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE') "
                "ORDER BY permission_name"
            )
            permissions = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT USER_NAME(), SUSER_SNAME()")
            database_user, sql_identity = cursor.fetchone()
            return api_response({
                "databaseUser": database_user,
                "sqlIdentity": sql_identity,
                "databasePermissions": permissions,
            })
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.post("/api/sql/query")
def sql_query():
    payload = request.get_json(silent=True) or {}
    try:
        query = validate_query(str(payload.get("query", "")))
        with sql_connection(str(payload.get("server", "")), str(payload.get("database", ""))) as connection:
            cursor = connection.cursor()
            cursor.execute(query)
            if not cursor.description:
                raise ValueError("The query did not return a result set.")
            columns = [column[0] for column in cursor.description]
            rows = [[str(value) if value is not None else None for value in row] for row in cursor.fetchmany(200)]
            return jsonify({"columns": columns, "rows": rows, "limit": 200})
    except ValueError as error:
        return api_error(str(error))
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/api/abfs/tables")
def abfs_tables():
    try:
        workspace = request.args.get("workspace", "").strip()
        item = request.args.get("item", "").strip()
        item_type = request.args.get("itemType", "Lakehouse").strip()
        if not workspace or not item or item_type not in {"Lakehouse", "Warehouse"}:
            raise ValueError("Choose a Lakehouse or Warehouse before checking OneLake paths.")
        root = f"{item}.{item_type}"
        tables_root = f"{root}/Tables"
        service = DataLakeServiceClient(account_url=f"https://{ONELAKE_HOST}", credential=credential())
        paths = service.get_file_system_client(workspace).get_paths(path=tables_root, recursive=True)
        tables = sorted({entry.name.removeprefix(f"{tables_root}/").removesuffix("/_delta_log") for entry in paths if entry.is_directory and entry.name.endswith("/_delta_log")})
        return api_response({"workspace": workspace, "itemPath": root, "tables": tables})
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.post("/api/abfs/preview")
def abfs_preview():
    payload = request.get_json(silent=True) or {}
    table = str(payload.get("table", "")).strip().strip("/")
    if not table or ".." in table or "\\" in table:
        return api_error("Choose a valid table path.")
    try:
        workspace = str(payload.get("workspace", "")).strip()
        item = str(payload.get("item", "")).strip()
        if not workspace or not item:
            raise ValueError("Choose a Lakehouse or Warehouse before reading OneLake data.")
        item_type = str(payload.get("itemType", "Lakehouse")).strip()
        path = f"{item}.{item_type}/Tables/{table}"
        fs = DataLakeServiceClient(account_url=f"https://{ONELAKE_HOST}", credential=credential()).get_file_system_client(workspace)
        files = [entry for entry in fs.get_paths(path=path, recursive=True) if not entry.is_directory and entry.name.endswith(".parquet") and "_delta_log" not in entry.name]
        if not files:
            raise ValueError("No readable Parquet files were found for this table.")
        target = min(files, key=lambda entry: entry.content_length or 0)
        content = fs.get_file_client(target.name).download_file().readall()
        preview = pq.read_table(io.BytesIO(content)).slice(0, 100)
        return jsonify({"file": target.name, "columns": preview.column_names, "rows": preview.to_pylist(), "rowCount": preview.num_rows})
    except ValueError as error:
        return api_error(str(error))
    except Exception as error:
        return api_error(safe_error(error), 502)


@app.get("/")
@app.get("/<path:filename>")
def site(filename: str = "index.html"):
    """Serve the static UI after all API routes have been registered."""
    if filename.startswith("api/"):
        return api_error("Not found.", 404)
    if filename == "lakehouses.html":
        page = (SITE / filename).read_text(encoding="utf-8")
        disclaimer = (
            '<p style="font-style:italic;color:#60708a;line-height:1.5;'
            'margin:28px auto;width:min(1060px,calc(100% - 32px))">'
            'Fabric item permission automation is planned for a future Fabric API '
            'release. Once supported write APIs are available, this app can grant '
            'and revoke item access automatically.</p>'
        )
        loading_ui = '''<style>.refreshing-button{position:relative;padding-left:34px!important}.refreshing-button::before{content:"";position:absolute;left:12px;top:50%;width:13px;height:13px;margin-top:-7px;border:2px solid #d8d0fc;border-top-color:#5b3cc4;border-radius:50%;animation:item-spin .75s linear infinite}.item-loading{display:inline-flex!important;align-items:center;gap:9px}.item-loading::before{content:"";width:16px;height:16px;border:2px solid #d8d0fc;border-top-color:#5b3cc4;border-radius:50%;animation:item-spin .75s linear infinite}@keyframes item-spin{to{transform:rotate(360deg)}}</style><script>(()=>{const button=document.getElementById('refresh'),count=document.getElementById('count'),items=document.getElementById('items');if(!button||!count)return;const sync=()=>{const busy=count.textContent.startsWith('Checking');count.classList.toggle('item-loading',busy);if(!busy){button.disabled=false;button.classList.remove('refreshing-button');button.textContent='Refresh'}};button.addEventListener('click',()=>{button.disabled=true;button.classList.add('refreshing-button');button.textContent='Refreshing...';count.textContent='Checking permissions for this user...';if(items)items.innerHTML=''},true);new MutationObserver(sync).observe(count,{childList:true,characterData:true,subtree:true});sync()})()</script>'''
        return Response(page.replace("</main>", f"</main>{disclaimer}{loading_ui}"), mimetype="text/html")
    if filename == "index.html":
        page = (SITE / filename).read_text(encoding="utf-8")
        guide_link = (
            '<p style="margin:20px 0 0"><a href="setup-guide.html" '
            'style="color:#5b3cc4;font-weight:800">Open setup guide &rarr;</a></p>'
        )
        return Response(page.replace("</header>", f"{guide_link}</header>"), mimetype="text/html")
    if filename == "setup-guide.html":
        page = (SITE / filename).read_text(encoding="utf-8")
        sql_scripts = '''<style>.sql-script-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:18px}.sql-script{padding:16px;border:1px solid #dce4ef;border-radius:12px;background:#fafbfe}.sql-script h3{margin:0 0 8px;font-size:18px}.sql-script p{color:#60708a;line-height:1.45}.sql-script pre{max-height:300px;overflow:auto;padding:12px;border-radius:8px;background:#111827;color:#e5edf9;font:12px/1.5 Consolas,"Courier New",monospace;white-space:pre}.copy-script{margin-top:12px;padding:8px 12px;border:1px solid #5b3cc4;border-radius:7px;background:#fff;color:#5b3cc4;font:inherit;font-weight:750;cursor:pointer}@media(max-width:900px){.sql-script-grid{grid-template-columns:1fr}}</style><script>(()=>{const section=[...document.querySelectorAll('.section')].find(x=>x.querySelector('h2')?.textContent==='4. Configure SQL permissions');if(!section)return;const scripts=[{title:'Grant table permissions',text:`-- Replace placeholders before running.\nGRANT SELECT ON OBJECT::[<schema>].[<table>]\nTO [<user-or-service-principal>];\nGO`},{title:'Apply row-level security',text:`-- Create a filter predicate function, then apply it to a table.\nCREATE SCHEMA Security;\nGO\nCREATE FUNCTION Security.fn_FilterRows (@Region nvarchar(100))\nRETURNS TABLE\nWITH SCHEMABINDING\nAS\nRETURN SELECT 1 AS AllowedRow\nWHERE @Region = N'<allowed-region>'\n  AND USER_NAME() = N'<user-or-service-principal>';\nGO\nCREATE SECURITY POLICY Security.RowFilterPolicy\nADD FILTER PREDICATE Security.fn_FilterRows([<column>])\nON [<schema>].[<table>]\nWITH (STATE = ON);\nGO`},{title:'Apply column-level security',text:`-- Grant access only to approved columns.\nREVOKE SELECT ON OBJECT::[<schema>].[<table>]\nFROM [<user-or-service-principal>];\nGO\nGRANT SELECT ON OBJECT::[<schema>].[<table>]\n([<column-1>], [<column-2>])\nTO [<user-or-service-principal>];\nGO`}];section.innerHTML='<span class="plane data">Data plane permissions</span><h2>4. Configure SQL permissions</h2><p>Use SQL security to grant table, row, or column access for the selected identity.</p><div class="sql-script-grid">'+scripts.map((script,index)=>'<article class="sql-script"><h3>'+script.title+'</h3><pre id="sqlScript'+index+'"></pre><button class="copy-script" data-script="sqlScript'+index+'">Copy script</button></article>').join('')+'</div><div class="note sql">Replace every value in angle brackets before running a script. Validate SQL and ABFS separately after changing permissions.</div>';scripts.forEach((script,index)=>document.getElementById('sqlScript'+index).textContent=script.text);section.querySelectorAll('.copy-script').forEach(button=>button.onclick=async()=>{await navigator.clipboard.writeText(document.getElementById(button.dataset.script).textContent);const original=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=original,1200)})})()</script>'''
        return Response(page.replace("</body>", f"{sql_scripts}</body>"), mimetype="text/html")
    if filename in {"lakehouses.html", "sql-simulator.html", "abfs-simulator.html"}:
        page = (SITE / filename).read_text(encoding="utf-8")
        loading_ui = '''<style>.loading-spinner{display:inline-flex!important;align-items:center;gap:8px}.loading-spinner::before{content:"";width:13px;height:13px;border:2px solid #d8d0fc;border-top-color:#5b3cc4;border-radius:50%;animation:loading-spin .75s linear infinite}@keyframes loading-spin{to{transform:rotate(360deg)}}.refreshing-button{position:relative;padding-left:34px!important}.refreshing-button::before{content:"";position:absolute;left:12px;top:50%;width:13px;height:13px;margin-top:-7px;border:2px solid #d8d0fc;border-top-color:#5b3cc4;border-radius:50%;animation:loading-spin .75s linear infinite}.abfs-reading{position:relative;padding-left:34px!important}.abfs-reading::before{content:"";position:absolute;left:12px;top:50%;width:13px;height:13px;margin-top:-7px;border:2px solid #b9dfd9;border-top-color:#087b72;border-radius:50%;animation:loading-spin .75s linear infinite}</style><script>(()=>{const watch=(element,condition,className='loading-spinner')=>{if(!element)return;new MutationObserver(()=>element.classList.toggle(className,condition(element.textContent))).observe(element,{childList:true,characterData:true,subtree:true});element.classList.toggle(className,condition(element.textContent))};const refresh=document.getElementById('refresh');if(refresh){refresh.addEventListener('click',()=>{refresh.disabled=true;refresh.classList.add('refreshing-button');refresh.textContent='Refreshing...'},true);watch(document.getElementById('count'),text=>{const busy=text.startsWith('Checking');if(!busy){refresh.disabled=false;refresh.classList.remove('refreshing-button');refresh.textContent='Refresh'}return busy})}watch(document.getElementById('queryStatus'),text=>text.startsWith('Executing'));watch(document.getElementById('message'),text=>text.startsWith('Loading')||text.startsWith('Refreshing'));watch(document.getElementById('pull'),text=>text.startsWith('Reading'),'abfs-reading')})()</script>'''
        return Response(page.replace("</body>", f"{loading_ui}</body>"), mimetype="text/html")
    return send_from_directory(SITE, filename)


@app.get("/images/<path:filename>")
def images(filename: str):
    return send_from_directory(ROOT / "images", filename)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
