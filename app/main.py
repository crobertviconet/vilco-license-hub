import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.database import get_db, init_db
from app.security import (
    PUBLIC_KEY_B64,
    check_rate_limit,
    clear_failed_logins,
    create_session_token,
    generate_robust_license_key,
    register_failed_login,
    sign_license_certificate,
    verify_password,
    verify_session_token,
)

app = FastAPI(title="VilcoLicense Hub", version="1.0.1")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def on_startup():
    init_db()


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateAppRequest(BaseModel):
    app_code: str = Field(..., min_length=3, max_length=30)
    name: str
    description: str = ""


class CreateLicenseRequest(BaseModel):
    app_code: str = "AEGIS_VAULT"
    customer_name: str
    customer_email: str = ""
    max_devices: int = Field(2, ge=1, le=50)
    expires_at: Optional[str] = None
    notes: str = ""


class UpdateLicenseStatusRequest(BaseModel):
    status: str


class CreateReleaseRequest(BaseModel):
    app_code: str = "AEGIS_VAULT"
    platform: str
    version: str
    build_number: int = Field(..., ge=1)
    download_url: str
    sha256_hash: str = Field(..., min_length=64, max_length=64)
    changelog: str = ""
    force_update: bool = False


class ActivateRequest(BaseModel):
    license_key: str
    app_code: str
    device_fingerprint: str = Field(..., min_length=16, max_length=128)
    device_name: str = "Dispositivo"
    platform: str = "android"
    app_version: str = "1.0.0"


def log_audit(db, actor: str, action: str, detail: str, ip: str = ""):
    db.execute(
        "INSERT INTO audit_logs (actor, action, detail, ip_address) VALUES (?, ?, ?, ?)",
        (actor, action, detail, ip),
    )


def get_current_user(request: Request) -> dict:
    token = request.cookies.get("vilco_session")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")
    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sesión inválida o expirada")
    return payload


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado: solo administradores")
    return user


@app.get("/")
def serve_panel():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/v1/public/meta")
def public_meta():
    db = get_db()
    try:
        rows = db.execute("SELECT key, value FROM config_params").fetchall()
        cfg = {dict(r)["key"]: dict(r)["value"] for r in rows}
        return {
            "brand": cfg.get("brand_name", "@VilcoSystem"),
            "hub_version": cfg.get("hub_version", "1.0.1"),
            "ed25519_public_key_b64": PUBLIC_KEY_B64,
        }
    finally:
        db.close()


@app.post("/api/v1/licenses/activate")
def activate_license(req: ActivateRequest, request: Request):
    ip = request.client.host if request.client else ""
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM licenses WHERE license_key = ? AND app_code = ?",
            (req.license_key.strip().upper(), req.app_code.strip().upper()),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Licencia no encontrada para esta aplicación")

        lic = dict(row)
        if lic.get("status") != "ACTIVE":
            raise HTTPException(status_code=403, detail=f"Licencia en estado {lic.get('status')}")

        expires_at = lic.get("expires_at")
        if expires_at:
            exp_dt = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                raise HTTPException(status_code=403, detail="Licencia expirada")

        dev_row = db.execute(
            "SELECT * FROM devices WHERE license_id = ? AND device_fingerprint = ?",
            (lic["id"], req.device_fingerprint),
        ).fetchone()

        now_iso = datetime.now(timezone.utc).isoformat()

        if dev_row:
            dev = dict(dev_row)
            if dev.get("status") != "ACTIVE":
                raise HTTPException(status_code=403, detail="Este dispositivo fue revocado por el administrador")
            db.execute(
                "UPDATE devices SET last_seen_at = ?, app_version = ?, device_name = ? WHERE id = ?",
                (now_iso, req.app_version, req.device_name, dev["id"]),
            )
        else:
            count_row = db.execute(
                "SELECT COUNT(*) as total FROM devices WHERE license_id = ? AND status = 'ACTIVE'",
                (lic["id"],),
            ).fetchone()
            active_count = dict(count_row)["total"]
            if active_count >= lic["max_devices"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Límite de dispositivos alcanzado ({active_count}/{lic['max_devices']})",
                )
            db.execute(
                """
                INSERT INTO devices (license_id, device_fingerprint, device_name, platform, app_version, activated_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (lic["id"], req.device_fingerprint, req.device_name, req.platform, req.app_version, now_iso, now_iso),
            )
            log_audit(db, "client", "DEVICE_ACTIVATED", f"{lic['license_key']} -> {req.device_name} ({req.platform})", ip)

        db.commit()

        cert_payload = {
            "license_key": lic["license_key"],
            "app_code": lic["app_code"],
            "customer_name": lic["customer_name"],
            "device_fingerprint": req.device_fingerprint,
            "max_devices": lic["max_devices"],
            "expires_at": expires_at,
            "issued_at": now_iso,
        }
        return sign_license_certificate(cert_payload)
    finally:
        db.close()


@app.get("/api/v1/updates/check")
def check_updates(app_code: str, platform: str, build: int):
    db = get_db()
    try:
        row = db.execute(
            """
            SELECT * FROM releases
            WHERE app_code = ? AND platform = ?
            ORDER BY build_number DESC LIMIT 1
            """,
            (app_code.upper(), platform.lower()),
        ).fetchone()
        if not row:
            return {"update_available": False}

        rel = dict(row)
        if rel["build_number"] > build:
            return {
                "update_available": True,
                "version": rel["version"],
                "build_number": rel["build_number"],
                "download_url": rel["download_url"],
                "sha256_hash": rel["sha256_hash"],
                "changelog": rel.get("changelog", ""),
                "force_update": bool(rel.get("force_update", 0)),
            }
        return {"update_available": False, "latest_version": rel["version"]}
    finally:
        db.close()


@app.post("/api/admin/login")
def admin_login(req: LoginRequest, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="Demasiados intentos fallidos. Espera 1 minuto.")

    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),)).fetchone()
        if not row or not verify_password(req.password, dict(row)["password_hash"]):
            register_failed_login(ip)
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        clear_failed_logins(ip)
        user = dict(row)
        token = create_session_token(user["username"], user["role"])
        response.set_cookie(
            key="vilco_session",
            value=token,
            httponly=True,
            samesite="lax",
            secure=bool(os.getenv("RENDER")),
            max_age=60 * 60 * 12,
        )
        log_audit(db, user["username"], "LOGIN", f"Rol: {user['role']}", ip)
        db.commit()
        return {"username": user["username"], "role": user["role"]}
    finally:
        db.close()


@app.post("/api/admin/logout")
def admin_logout(response: Response):
    response.delete_cookie("vilco_session")
    return {"ok": True}


@app.get("/api/admin/me")
def admin_me(user: dict = Depends(get_current_user)):
    return user


@app.get("/api/admin/apps")
def list_apps(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        return [dict(r) for r in db.execute("SELECT * FROM apps ORDER BY id ASC").fetchall()]
    finally:
        db.close()


@app.post("/api/admin/apps")
def create_app(req: CreateAppRequest, request: Request, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        code = req.app_code.strip().upper()
        db.execute(
            "INSERT INTO apps (app_code, name, description) VALUES (?, ?, ?)",
            (code, req.name.strip(), req.description.strip()),
        )
        log_audit(db, user["sub"], "CREATE_APP", code, request.client.host if request.client else "")
        db.commit()
        return {"ok": True, "app_code": code}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al crear app: {e}")
    finally:
        db.close()


@app.get("/api/admin/licenses")
def list_licenses(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute(
            """
            SELECT l.*,
                   (SELECT COUNT(*) FROM devices d WHERE d.license_id = l.id AND d.status = 'ACTIVE') AS active_devices
            FROM licenses l
            ORDER BY l.id DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


@app.post("/api/admin/licenses")
def create_license(req: CreateLicenseRequest, request: Request, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        app_code = req.app_code.strip().upper()
        key = generate_robust_license_key(app_code[:4])
        db.execute(
            """
            INSERT INTO licenses (license_key, app_code, customer_name, customer_email, max_devices, expires_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (key, app_code, req.customer_name.strip(), req.customer_email.strip(), req.max_devices, req.expires_at or None, req.notes.strip()),
        )
        log_audit(db, user["sub"], "CREATE_LICENSE", f"{key} ({req.customer_name}, max={req.max_devices})", request.client.host if request.client else "")
        db.commit()
        return {"ok": True, "license_key": key}
    finally:
        db.close()


@app.patch("/api/admin/licenses/{license_id}/status")
def update_license_status(license_id: int, req: UpdateLicenseStatusRequest, request: Request, user: dict = Depends(require_admin)):
    if req.status not in ("ACTIVE", "SUSPENDED", "REVOKED"):
        raise HTTPException(status_code=400, detail="Estado inválido")
    db = get_db()
    try:
        db.execute("UPDATE licenses SET status = ? WHERE id = ?", (req.status, license_id))
        log_audit(db, user["sub"], "LICENSE_STATUS", f"ID {license_id} -> {req.status}", request.client.host if request.client else "")
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@app.get("/api/admin/licenses/{license_id}/devices")
def list_devices(license_id: int, user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM devices WHERE license_id = ? ORDER BY id DESC", (license_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


@app.patch("/api/admin/devices/{device_id}/revoke")
def revoke_device(device_id: int, request: Request, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        db.execute("UPDATE devices SET status = 'REVOKED' WHERE id = ?", (device_id,))
        log_audit(db, user["sub"], "REVOKE_DEVICE", f"Device ID {device_id}", request.client.host if request.client else "")
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@app.get("/api/admin/releases")
def list_releases(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM releases ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


@app.post("/api/admin/releases")
def create_release(req: CreateReleaseRequest, request: Request, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO releases (app_code, platform, version, build_number, download_url, sha256_hash, changelog, force_update)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.app_code.upper(),
                req.platform.lower(),
                req.version.strip(),
                req.build_number,
                req.download_url.strip(),
                req.sha256_hash.strip().lower(),
                req.changelog.strip(),
                1 if req.force_update else 0,
            ),
        )
        log_audit(db, user["sub"], "PUBLISH_RELEASE", f"{req.app_code} {req.platform} v{req.version} (b{req.build_number})", request.client.host if request.client else "")
        db.commit()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al publicar versión: {e}")
    finally:
        db.close()


@app.get("/api/admin/audit")
def list_audit(user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()
