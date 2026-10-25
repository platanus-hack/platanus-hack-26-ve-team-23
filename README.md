# HAWK

**Hardware Autonomous Watcher & Keeper** (nombre tentativo).

Un monitor de control para agentes de programación que vive en un equipo
aparte. Frena las acciones peligrosas del agente antes de que se ejecuten,
aísla la máquina en el firewall de la red cuando el agente intenta saltárselo
y guarda un registro que el agente no puede reescribir, verificado desde el
teléfono del dueño.

Platanus Hack 26: Caracas. Track: AI Security (AI control). Equipo 23.

<img src="./project-logo.png" alt="Logo de HAWK" width="200" />

Sitio, guía de instalación y descargas: [hawkeeper.xyz](https://hawkeeper.xyz).

> **Estado.** Funciona de punta a punta. Claude Code y Codex (con un hook) y
> OpenCode (con un plugin) le preguntan al daemon de la máquina antes de cada
> herramienta. El daemon reenvía la consulta por QUIC con TLS mutuo al Core,
> que decide con un catálogo de 12 reglas, sella y encadena cada decisión,
> firma las cabeceras (Ed25519 + ML-DSA-65) y aísla máquinas en el firewall,
> también la que deja de responder a su latido. La app del dueño encuentra el
> Core en la red, lo activa con un asistente, aprueba máquinas, fija los
> umbrales de atención, verifica las firmas y puede hacer que cualquier
> máquina vigilada se identifique. Una etapa de familiaridad, destilada del
> corpus de entrenamiento, puede negar comandos desconocidos (opcional,
> `HAWK_CLASSIFIER=1`, ADR-0036). El clasificador Granite está entrenado;
> ADR-0037 decide cómo correrá dentro del Core y todavía no está construido.
> Faltan la atestación con TPM y los sensores de kernel: ver
> [`docs/ROADMAP.md`](docs/ROADMAP.md). Decisiones:
> [`docs/adr`](docs/adr/README.md). Flujo completo:
> [`docs/ACTION-TREE.md`](docs/ACTION-TREE.md).

## El problema

Los filtros de los proveedores revisan lo que el modelo dice. No ven lo que
el agente hace con sus herramientas (borrar un registro, mandar un secreto por
la red, apagar su propio monitor), y sus registros viven donde ni el dueño ni
un auditor pueden comprobarlos por su cuenta. Un monitor que corre en la
misma máquina que el agente puede ser apagado por ese agente.

HAWK controla al agente, no al modelo
([ADR-0002](docs/adr/0002-control-the-agent-not-the-model.md)): cubre la capa
de acciones y evidencia que los filtros de contenido no cubren. Separar quién
ejecuta de quién decide es lo mismo que hacen el Secure Enclave de Apple, el
TPM o los HSM de la banca
([ADR-0003](docs/adr/0003-three-device-topology.md)).

## Los tres equipos

```
 Máquina vigilada                   Core (Raspberry Pi)                   Teléfono del dueño
 agente --hook--> daemon ==QUIC==> decide: reglas + política   <==QUIC== app HAWK
          loopback   | identidad    sella, encadena y firma                activa (asistente)
                     | fijada       aísla en el firewall                   panel, verifica firmas
          aviso <----+--- identificar -- máquinas por huella  <-- identificar -- encuentra una máquina
```

- **Core** (`guardian`): decide, registra y aísla. No hace nada hasta que la
  app del dueño lo empareja
  ([ADR-0017](docs/adr/0017-core-pairing-and-passkeys.md)).
- **Daemon** (`host-daemon`): corre en cada máquina vigilada. Reenvía el hook
  del agente y no tiene interfaz, salvo el aviso de identificación.
- **App del dueño** (`witness`): la app del teléfono que controla todo (APK;
  hay una versión de escritorio para desarrollo).

Cada enlace entre ellos es QUIC con TLS 1.3 mutuo, y la llave Ed25519 de cada
certificado es la identidad
([ADR-0023](docs/adr/0023-quic-with-mutual-tls-between-edges.md)). El Core se
anuncia por mDNS y la app lo activa con un asistente: nadie escribe
direcciones ([ADR-0024](docs/adr/0024-discovery-and-activation-wizard.md)).

## Cómo fluye una llamada

1. Antes de usar una herramienta, el agente le pregunta al daemon: Claude Code
   y Codex con `hawk-host-daemon hook`, OpenCode con su plugin por loopback.
   Si el daemon no responde, la herramienta no se ejecuta.
2. El daemon reenvía la llamada al Core por QUIC, fijado a la identidad del
   Core. Si no llega al Core, niega.
3. El Core evalúa la llamada con las reglas (y la etapa de clasificación si
   está activa); la severidad más alta decide: permitir, preguntarle al dueño,
   negar, o negar y aislar
   ([ADR-0022](docs/adr/0022-decision-policy-severities-and-defaults.md)).
4. Cada decisión se sella con la llave semanal del dueño, se agrega a una
   cadena de hashes y queda cubierta por cabeceras firmadas con Ed25519 y
   ML-DSA-65 ([ADR-0019](docs/adr/0019-post-quantum-signatures-on-heads.md)).
   El Core escribe el registro, pero no lo puede leer.
5. Ante un hallazgo crítico, el Core pone la máquina en la lista de
   cuarentena del firewall de la red (OpenWrt, MikroTik; Cisco después), así
   que incluso una máquina con root queda cortada
   ([ADR-0018](docs/adr/0018-network-containment-through-the-firewall.md)).
6. Los metadatos de cada evento pueden ir a Kafka o a un webhook
   ([ADR-0020](docs/adr/0020-integrations-firewalls-and-event-sinks.md)).

**Prevenir, no solo registrar.** Una caja negra te dice por qué se cayó el
avión; HAWK frena la acción antes de que ocurra. Un registro sellado en la
máquina infectada solo prueba lo que el atacante le dejó sellar; HAWK sella en
otro equipo.

## Componentes

Workspace de Rust ([ADR-0012](docs/adr/0012-rust-workspace-and-crate-boundaries.md)),
app en Tauri 2 ([ADR-0013](docs/adr/0013-tauri-front-end.md)), monitor propio
sobre primitivas establecidas
([ADR-0014](docs/adr/0014-own-implementation-established-primitives.md)).

| Capa | Crate | Corre en | Responsabilidad |
|---|---|---|---|
| Registro y protocolo | [guardian-core](guardian-core/README.md) | todos | Eventos, cadena de hashes, cabeceras firmadas, sellado, mensajes. Sin E/S |
| Detección | [detect](detect/README.md) | Core | Motor de reglas, política, catálogo de 12 reglas (`detect/rules/default.json`) y etapa de familiaridad |
| Red | [edge-net](edge-net/README.md) | todos | QUIC con TLS mutuo, descubrimiento mDNS, HTTP por loopback |
| Integraciones | [integrations](integrations/README.md) | Core | Firewalls (modo prueba, MikroTik, OpenWrt), Kafka y webhook |
| Core | [guardian](guardian/README.md) | Raspberry Pi | Emparejamiento, decisiones, registro, aislamiento, máquinas, identificación |
| Daemon | [host-daemon](host-daemon/README.md) | máquinas vigiladas | Reenvío por QUIC, hooks de Claude Code y Codex, Core fijado, aviso de identificación |
| App del dueño | [witness](witness/README.md) | teléfono (APK), escritorio | Activación, panel, aprobaciones, umbrales, verificación, identificación |
| Hook del agente | [agent-hook](agent-hook/README.md) | máquinas vigiladas | Plugin mínimo de OpenCode en TypeScript; falla cerrado |
| Proxy LLM | [llm-proxy](llm-proxy/README.md) | daemon | Reenvío, streaming SSE y extracción de llamadas para el cruce con el hook |
| Evaluación | [eval](eval/README.md) | PC + Core | Set de tareas (15 legítimas, 15 dañinas), ejecutor y métricas |
| Entrenamiento | [training](training/README.md) | PC con GPU | Dataset, línea base y Granite 4 con LoRA (ADR-0035) |

## Instalación

La guía completa está en [hawkeeper.xyz](https://hawkeeper.xyz). En resumen:

1. El Core en una Raspberry Pi 4, o en otro equipo dedicado con Linux de 64
   bits que no sea una de las máquinas vigiladas.
2. La app en el teléfono (APK) o en el escritorio; empareja el Core
   comparando su huella y un código de seis dígitos.
3. En cada máquina con Linux o macOS:
   `curl -fsSL https://hawkeeper.xyz/install.sh | sh` (en Windows, el `.zip`
   de las descargas).
4. Aprueba cada máquina en la app, comparando su huella.

## Compilar y correr

```sh
just check                  # fmt, clippy (los avisos son errores) y tests
just guardian               # el Core: QUIC en 0.0.0.0:7443, anunciado por mDNS
just probe 127.0.0.1:7443   # saludo QUIC contra un Core
just daemon                 # un daemon (GUARDIAN_CORE=ip:7443 para no buscar por mDNS)
just witness                # la app del dueño en el escritorio
just witness-apk            # la app como APK (Android SDK y NDK)
```

Para revisar el diseño de la app sin un Core, abre `witness/ui/index.html` en
un navegador (agrega `?wizard` para ver la activación).

## Qué no es HAWK

- No es un filtro de jailbreaks ni de contenido: no hace más seguro al modelo.
- No es una blockchain: la integridad viene de una cadena de hashes local y un
  testigo independiente
  ([ADR-0006](docs/adr/0006-local-hash-chain-no-blockchain.md)).
- No protege contra un agente con root en la PC; lo registrado hasta ese
  momento sobrevive fuera de ella.

## Documentación

La documentación técnica (ADRs, whitepaper) está en inglés.

| Qué | Dónde |
|---|---|
| Diseño y modelo de amenazas | [docs/WHITEPAPER.md](docs/WHITEPAPER.md) |
| Por qué funciona así (decisiones) | [docs/adr](docs/adr/README.md) |
| Hitos, estado y lo que falta | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Guion de la demo | [docs/DEMO.md](docs/DEMO.md) |
| Laboratorio de routers (VMs de MikroTik CHR y OpenWrt) | [docs/LAB.md](docs/LAB.md) |
| Entrenamiento del clasificador (Granite) | [docs/ENTRENAMIENTO-GRANITE.md](docs/ENTRENAMIENTO-GRANITE.md) |
| Costo de cada decisión | [docs/BENCHMARKS.md](docs/BENCHMARKS.md) |
| Nube opcional: archivo y configuración como código | [infra/README.md](infra/README.md) |
| Instrucciones para agentes de programación | [CLAUDE.md](CLAUDE.md) |
| Cómo se trabaja | [docs/standards](docs/standards/README.md), [CONTRIBUTING.md](CONTRIBUTING.md) |
| Reportar una vulnerabilidad | [SECURITY.md](SECURITY.md) |
| Qué cambió | [CHANGELOG.md](CHANGELOG.md) |

## Licencia

Todavía no está elegida; hasta entonces no se otorga ninguna. Sea cual sea,
cada dependencia debe usar una licencia de la lista de
[ADR-0011](docs/adr/0011-dependency-licences.md) (MIT, Apache-2.0, BSD, ISC y
similares; sin GPL, LGPL ni AGPL, sin licencias no comerciales), comprobado
con `just audit`.

## Equipo

- Javier Hernández ([@JEHR037](https://github.com/JEHR037))
- Elisaul Velásquez ([@elisaul170408-ai](https://github.com/elisaul170408-ai))
- Adrián Guevara ([@adrianegb](https://github.com/adrianegb))
- Aaron Chacón Rincones ([@chaconjrincones-star](https://github.com/chaconjrincones-star))
- Samuel Hernández ([@unkn0wn-cs](https://github.com/unkn0wn-cs))
