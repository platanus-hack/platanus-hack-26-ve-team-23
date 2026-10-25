# HAWK

**Tu agente ejecuta. HAWK revisa.** Hardware Autonomous Watcher & Keeper: un equipo aparte que
revisa cada acción de tus agentes de IA antes de que se ejecute.

## El problema

Un agente de programación trabaja con tus permisos. Puede borrar un registro, leer un `.env` y
mandarlo por la red, o apagar el monitor que lo vigila. Los filtros de los proveedores revisan lo
que el modelo dice, no lo que el agente hace con sus herramientas. Y un monitor que corre en la
misma computadora que el agente se puede apagar desde esa misma computadora.

## Cómo funciona

1. **Pregunta antes de ejecutar.** Claude Code y Codex, con un hook, y OpenCode, con un plugin, le
   preguntan al programa de HAWK en la computadora antes de cada herramienta. Ese programa reenvía
   la consulta por QUIC con TLS mutuo al Core, que corre en otro equipo: una Raspberry Pi o
   cualquier equipo dedicado con Linux de 64 bits.
2. **Decide con reglas.** El Core aplica un catálogo de reglas: borrar historial o registros, leer
   o enviar secretos, apagar el monitor, shells inversas, ofuscación y escrituras fuera del
   proyecto. Según la severidad, permite, te pregunta en la app (si no respondes en 60 segundos,
   niega), niega, o niega y aísla.
3. **Aísla la máquina.** Ante una acción crítica, le pide al router OpenWrt o MikroTik que saque la
   máquina de la red, por IP y por MAC. Si el programa de una computadora deja de responder a su
   latido, HAWK también la aísla: apagar el monitor no sirve para escapar.
4. **Guarda un registro que nadie reescribe.** Cada decisión se sella con la llave semanal de tu
   teléfono, se encadena por hash, entra en un árbol Merkle por lote y se firma con Ed25519 y
   ML-DSA-65 (poscuántica). El Core escribe el registro, pero no lo puede leer. La app verifica las
   firmas contra la identidad que guardó al emparejar.

**Falla cerrado.** Ante un error, un tiempo agotado, una entrada malformada o un HAWK sin
emparejar, la acción no se ejecuta. Lo que ninguna regla reconoce se permite y queda registrado.

## Tu teléfono manda

- Encuentra HAWK en la red local y lo activa contigo: comparas la huella y un código de seis
  dígitos que ven los dos lados.
- Aprueba cada computadora por su huella. Una computadora sin aprobar no pasa.
- Eliges desde qué severidad te pregunta y desde cuál niega. Una acción crítica siempre se niega y
  aísla, y el cambio queda firmado y registrado.
- **Identificar** hace que una máquina muestre un aviso en su pantalla, para encontrarla entre
  decenas.
- Libera una máquina aislada cuando lo decides tú.

## Qué es real en la demo y qué no

- **Funciona de punta a punta:** el Core, el programa para Windows, macOS y Linux, la app para
  Android y escritorio, los hooks de Claude Code, Codex y OpenCode, las reglas, la aprobación de
  computadoras, el latido y el registro sellado y firmado.
- **Descargas reales:** cada versión se compila en GitHub Actions para Linux (x86_64 y ARM64),
  macOS, Windows y Android, con `SHA256SUMS`, en [hawkeeper.xyz](https://hawkeeper.xyz).
- **Aislamiento:** hay adaptadores para OpenWrt y MikroTik. Sin un router compatible, corre en modo
  de prueba y registra a quién habría aislado.
- **Copia fuera de la placa, opcional:** HAWK puede archivar cada lote firmado en un almacenamiento
  compatible con S3 con Object Lock. Viaja sellado: el almacenamiento guarda datos que no puede
  leer. Sin nube, HAWK sigue igual.
- **Todavía no:** un modelo local pequeño, de la clase Granite 4 con unos 800 millones de
  parámetros, para clasificar lo que las reglas no resuelven. El modelo ya está entrenado, pero
  todavía no corre en el Core: hoy decide con reglas. Tampoco están la identidad de cada
  computadora en su TPM ni la configuración firmada para equipos.
- **Límites:** un agente sin hooks no pasa por HAWK. HAWK no hace más seguro al modelo: controla al
  agente. No protege contra un agente con root en la computadora, pero lo registrado hasta ese
  momento ya está fuera de ella.

## Instalación

1. Descarga el Core en la Raspberry Pi o en el equipo dedicado y arráncalo.
2. Instala la app y actívalo.
3. En cada computadora con Linux o macOS: `curl -fsSL https://hawkeeper.xyz/install.sh | sh`. En
   Windows, el `.zip` de las descargas.
4. Aprueba cada computadora en la app.

La guía completa y las descargas están en [hawkeeper.xyz](https://hawkeeper.xyz).

## Tecnología

Rust con tokio · QUIC con quinn y TLS 1.3 mutuo con rustls · descubrimiento por mDNS · Ed25519 y
ML-DSA-65 para las firmas · X25519 y ChaCha20-Poly1305 para el sellado · Tauri 2 con HTML, CSS y
JavaScript para la app · GitHub Actions para compilar y publicar · Render para el sitio. Todas las
dependencias tienen licencias permisivas, comprobadas con `cargo deny`. Cada decisión de diseño
está escrita en un ADR en `docs/adr`.

## Equipo

team-23 · Platanus Hack 26 Caracas · Track AI Security: Javier Hernández, Elisaul Velásquez,
Adrián Guevara, Aaron Chacón y Samuel Hernández.
