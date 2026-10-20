# Financia

Aplicación web en español para guardar y organizar documentos financieros. Incluye cuentas por correo y contraseña, inicio de sesión OAuth con Google/Apple, passkeys biométricas WebAuthn, aislamiento de documentos por cuenta y cifrado de los archivos almacenados.

## Requisitos

- Python 3.10 o posterior.
- HTTPS para publicar la aplicación y habilitar passkeys fuera de `localhost`.
- Credenciales de OAuth de Google y/o Apple para mostrar esos métodos de inicio de sesión.

## Ejecutar en Windows

1. Crea y activa un entorno virtual:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Instala las dependencias e inicia la aplicación:

   ```powershell
   pip install -r requirements.txt
   python app.py
   ```

3. Abre http://127.0.0.1:5000. En el primer registro, esa cuenta recibe los documentos que ya existían en la instalación.

No abras `index.html` directamente como archivo (`file://`): la aplicación necesita Flask para cargar sus recursos, iniciar sesión y acceder a los documentos. Abre siempre la dirección `http://127.0.0.1:5000` mientras `python app.py` esté en ejecución.

La aplicación genera una clave local en `data\.encryption.key` si no se configura una. Para una instalación publicada, configura claves persistentes desde el entorno, no desde el código:

```powershell
$env:FINANCIA_SECRET_KEY = "<secreto aleatorio persistente para firmar sesiones>"
$env:FINANCIA_ENCRYPTION_KEY = "<clave Fernet persistente para cifrar archivos>"
$env:FINANCIA_PREVIOUS_ENCRYPTION_KEY = "<clave anterior, solo durante una rotación>"
$env:FINANCIA_COOKIE_SECURE = "1"
$env:FLASK_ENV = "production"
$env:FINANCIA_ORIGIN = "https://financia.le.com"
$env:FINANCIA_RP_ID = "financia.le.com"
```

Para abrir la aplicación en `https://financia.le.com`, el dominio debe apuntar mediante DNS a un servidor o plataforma donde esté desplegada la aplicación, y ese alojamiento debe tener HTTPS/TLS configurado. Cambiar estos valores no registra el dominio ni publica la aplicación. `python app.py` sigue siendo únicamente para desarrollo local; consulta las instrucciones de tu proveedor para desplegar Flask con un servidor WSGI y proxy HTTPS.

Genera los secretos con un administrador de secretos o una herramienta local segura. La clave Fernet puede generarse con `Fernet.generate_key()` de la dependencia `cryptography`. Guarda copias de seguridad protegidas de ambas claves: perder la clave Fernet impide descifrar los documentos. Al rotar una clave, configura la anterior como `FINANCIA_PREVIOUS_ENCRYPTION_KEY`; el servidor seguirá descifrando los documentos antiguos y cifrará las cargas nuevas con la clave actual. Conserva la clave anterior mientras existan archivos cifrados con ella o vuelve a cifrarlos antes de retirarla.

## Configurar Google y Apple

Define las credenciales en el entorno del servidor. Los botones solo aparecen cuando las variables requeridas para ese proveedor están configuradas.

Google:

```text
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
```

Añade `https://financia.le.com/api/auth/oauth/google/callback` a las URI de redirección autorizadas en la consola de Google.

Apple:

```text
APPLE_CLIENT_ID
APPLE_TEAM_ID
APPLE_KEY_ID
APPLE_PRIVATE_KEY
```

Registra `https://financia.le.com/api/auth/oauth/apple/callback` como URL de retorno en Apple Developer. `APPLE_PRIVATE_KEY` debe contener la clave privada de Sign in with Apple en formato PEM; en una variable de entorno, conserva los saltos de línea o represéntalos como `\n`.

El secreto JWT de Apple se genera al iniciar el servidor y vence a los 150 días; reinicia el servicio antes de esa fecha para renovarlo.

`FINANCIA_ORIGIN` debe ser el origen público exacto (esquema y host, sin ruta) y coincidir con las URI de retorno y el origen de WebAuthn. Configura TLS en un proxy inverso o plataforma de alojamiento; el servidor integrado de Flask es solo para desarrollo. No reenvíes tráfico de producción sin HTTPS.

## Passkeys y biometría

Después de iniciar sesión, selecciona **Activar huella o Face ID** en la barra superior para registrar una passkey del dispositivo. En el siguiente acceso, escribe el mismo correo en el campo de passkey y confirma con el mecanismo del sistema: huella, Face ID, PIN u otro verificador. La biometría no sale del dispositivo; el servidor guarda únicamente la clave pública de la passkey y el contador del autenticador. WebAuthn exige un navegador compatible y un contexto seguro (`HTTPS` o `localhost`).

## Almacenamiento y seguridad

- Los documentos están aislados por cuenta y solo se sirven mediante rutas autenticadas. Las sesiones usan tokens aleatorios en cookies `HttpOnly`, `SameSite=Lax`, con protección CSRF para las operaciones de escritura.
- Las contraseñas se guardan con hash seguro; los archivos se cifran con Fernet antes de escribirse en `uploads\`. La primera cuenta también cifra los archivos heredados.
- El repositorio clasifica documentos como facturas, recibos, contratos, estados de cuenta u otros. Los recibos pueden vincularse a un gasto con proveedor, monto, fecha y categoría; los datos vinculados pueden revisarse y corregirse.
- El OCR se ejecuta localmente en imágenes JPG, JPEG y PNG: el texto reconocido se mantiene en memoria y no se guarda ni se envía a servicios externos. Si Tesseract no está instalado, los archivos siguen subiéndose cifrados y sus datos se pueden capturar manualmente.
- Para habilitar OCR en Windows instala Tesseract OCR con los datos de idioma español e inglés. Por ejemplo, si ya tienes Winget: `winget install --id UB-Mannheim.TesseractOCR`. La aplicación detecta automáticamente Tesseract en `PATH`, `%LOCALAPPDATA%\Tesseract-OCR\` y las carpetas habituales de Archivos de programa. Si lo instalas en otra ubicación, establece `$env:TESSERACT_CMD = "C:\ruta\Tesseract-OCR\tesseract.exe"`. Los idiomas predeterminados son `spa+eng`; si instalas otros datos, cámbialos con `$env:FINANCIA_OCR_LANG`.
- La base SQLite conserva metadatos necesarios para buscar y mostrar documentos (por ejemplo, correos, nombres, tamaños y fechas); esos metadatos no están cifrados campo por campo.
- El registro por correo no envía un correo de verificación ni incluye recuperación de contraseña. Añade esos flujos antes de usar el servicio como plataforma pública.
- Usa claves estables y respaldadas en producción, TLS, actualizaciones de dependencias y un servidor WSGI/proxy de producción. No uses el servidor de desarrollo de Flask para exponer la aplicación a Internet.

## Transacciones, gastos y costos

En el panel **Gastos y costos** puedes registrar egresos en COP y clasificarlos por separado:

- **Gastos operativos y administrativos:** renta, servicios, marketing, administración, impuestos, seguros, servicios profesionales, comisiones, suministros y categorías personales. Marca cada gasto como fijo o variable.
- **Costos directos:** materia prima, mano de obra directa, adquisición u otros costos vinculados a la producción o al servicio.
- **Comprobantes:** asocia un documento guardado a una transacción. Los datos OCR de un recibo también se registran en el libro de transacciones; al actualizar o eliminar el vínculo, el recibo y el gasto se mantienen sincronizados.
- **Transacciones recurrentes:** programa movimientos semanales, mensuales o anuales. El servidor genera los movimientos vencidos mientras la aplicación está en ejecución; la generación es idempotente para evitar duplicados.
- **Extractos bancarios de Colombia:** por ahora la importación es manual mediante CSV. El archivo debe estar codificado en UTF-8 y tener encabezados `fecha`, `descripcion`, `monto` y `tipo` (`gasto` o `costo`); también admite `proveedor`, `categoria`, `naturaleza` y `tipo_costo`. Las fechas admiten `AAAA-MM-DD` o `DD/MM/AAAA`. La misma importación se reconoce por el contenido del archivo y omite filas ya cargadas. Los ingresos y tipos ambiguos se rechazan en vez de clasificarse como gastos.

La conexión bancaria automática con Plaid o Belvo **no está implementada**; requiere credenciales y habilitación del proveedor para Colombia. Las transacciones, extractos importados y recurrencias se guardan en la base SQLite local por cuenta.

## Presupuestos y simulador

Define un presupuesto mensual por categoría para gastos operativos o costos directos. El panel compara el límite con los egresos registrados durante el mes y muestra una alerta al alcanzar el 80%, además de indicar cuando se supera el límite. Los presupuestos se guardan por cuenta y categoría.

El simulador estima el impacto durante un horizonte de 1 a 60 meses combinando una reducción porcentual del gasto mensual observado en la categoría seleccionada, un beneficio mensual adicional estimado por el usuario y una inversión inicial. La proyección usa el gasto registrado en el mes actual como base; es una herramienta orientativa y no garantiza ahorros o rentabilidad.

## Formatos admitidos

CSV, XLS, XLSX, PDF, DOCX, TXT, PNG, JPG y JPEG. Cada carga puede pesar hasta 25 MB en total.
