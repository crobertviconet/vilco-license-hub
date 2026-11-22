# VilcoLicense Hub v1.0.0

Administrador centralizado de licencias multi-app, control de dispositivos y gestor de actualizaciones OTA para **AegisVault** y futuras aplicaciones de **@VilcoSystem**.

## Ejecución local
1. Copiar `.env.example` a `.env`
2. Crear entorno virtual e instalar dependencias:
   ```bash
   python -m venv venv
   pip install -r requirements.txt
   ```
3. Iniciar servidor:
   ```bash
   uvicorn app.main:app --reload
   ```
4. Abrir `http://127.0.0.1:8000` (Admin por defecto: `admin` / `AdminVilco2026!`).

## Despliegue en Render + Turso (Costo Cero)
1. Subir este repositorio a GitHub.
2. En Render: **New -> Blueprint** (detecta automáticamente `render.yaml`) o **Web Service (Docker)**.
3. Configurar las variables de entorno (`TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `ADMIN_INIT_PASSWORD`, `AUDITOR_INIT_PASSWORD`, `ED25519_PRIVATE_KEY_B64`).
