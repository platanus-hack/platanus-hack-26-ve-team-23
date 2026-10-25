# Laboratorio: máquinas virtuales para probar la contención

Guía práctica para el equipo (en español).
Monta en una PC con Windows 11 Pro (Hyper-V) los dos routers que soporta el
Core, cada uno con una máquina vigilada detrás, para probar la cuarentena de
punta a punta (ADR-0018, ADR-0020) sin hardware de red.

## Qué máquinas hacen falta

| VM | Para qué | Imagen | Recursos | Redes |
|---|---|---|---|---|
| `hawk-mikrotik` | Router MikroTik que el Core controla por REST | **RouterOS CHR 7.x** (la última estable de la rama 7) | 1 vCPU, 256 MB, disco de la imagen | WAN: `HAWK-LAN` · LAN: `HAWK-SEG-MT` |
| `hawk-openwrt` | Router OpenWrt que el Core controla por ubus | **OpenWrt x86/64, 24.10.x o posterior** (fw4/nftables desde 22.03) | 1 vCPU, 256 MB | WAN: `HAWK-LAN` · LAN: `HAWK-SEG-OW` |
| `agent-mt` | Máquina vigilada detrás del MikroTik | Ubuntu 24.04 Server o Desktop | 2 vCPU, 4 GB, 30 GB | `HAWK-SEG-MT` |
| `agent-ow` | Máquina vigilada detrás del OpenWrt | Ubuntu 24.04 | 2 vCPU, 4 GB, 30 GB | `HAWK-SEG-OW` |
| Core | Decide y contiene | La **Raspberry Pi** en la LAN física; para pruebas sin Pi, una VM Debian 12 en `HAWK-LAN` | Pi: 2 GB | `HAWK-LAN` |

- **No uses RouterOS v6 ni la vieja instalación "x86".** La API REST que usa
  el Core existe desde RouterOS 7.1. La v6 solo tiene la API binaria del
  puerto 8728, que el Core no implementa.
- **Licencia del CHR:** la gratuita limita la subida a 1 Mbit/s por
  interfaz, y las respuestas del modelo hacia la VM del agente pasan por el
  router. Para la demo activa la **prueba de 60 días sin límite** (requiere
  cuenta de MikroTik).
- Ollama sigue en la PC anfitriona con la RTX 4070; las VMs del agente
  llegan a él a través de su router.

## Topología

```
            LAN física (router de la casa u oficina)
   ┌──────────────┬───────────────┬──────────────────┬──────────────┐
   Raspberry Pi   Celular (app)   PC anfitriona       (Hyper-V: switch externo HAWK-LAN)
   Core :7443/udp                 Ollama :11434        │
                                                       ├── hawk-mikrotik WAN ── LAN 10.23.1.1/24 ── agent-mt 10.23.1.10
                                                       └── hawk-openwrt  WAN ── LAN 10.23.2.1/24 ── agent-ow 10.23.2.10
```

- `HAWK-LAN`: switch **externo** de Hyper-V puenteado a la placa de red de la
  PC, para que los routers virtuales estén en la misma red que la Pi y el
  celular. Da a cada router una IP fija en la LAN (en los ejemplos,
  `192.168.88.31` para MikroTik y `192.168.88.32` para OpenWrt, con el Core en
  `192.168.88.20`; ajusta a tu red).
- `HAWK-SEG-MT` y `HAWK-SEG-OW`: switches **privados**. Cada agente solo
  tiene salida por su router, así que el corte en el router es real.

### Regla importante: sin NAT entre los agentes y el Core

El Core pone en cuarentena la dirección del par QUIC que ve (nunca una que el
cliente declare). Si el router enmascara (NAT) el tráfico del agente hacia el
Core, el Core ve la IP del router, no la del agente, y la cuarentena
apuntaría al lugar equivocado. Por eso:

- Los routers **no** hacen NAT hacia la LAN física; solo enrutan.
- La Pi (y la PC anfitriona, para que Ollama responda) necesitan una ruta a
  cada segmento a través de su router:
  ```sh
  # En la Pi
  sudo ip route add 10.23.1.0/24 via 192.168.88.31
  sudo ip route add 10.23.2.0/24 via 192.168.88.32
  ```
  ```powershell
  # En la PC anfitriona (PowerShell como administrador)
  route -p add 10.23.1.0 mask 255.255.255.0 192.168.88.31
  route -p add 10.23.2.0 mask 255.255.255.0 192.168.88.32
  ```
- Si los agentes necesitan internet (instalar paquetes), enmascara solo el
  tráfico que **no** va a la LAN física (reglas abajo).

## 1. Crear los switches en Hyper-V

PowerShell como administrador (activa Hyper-V antes en "Características de
Windows" si no está):

```powershell
# Cambia "Ethernet" por el nombre de tu placa de red (Get-NetAdapter)
New-VMSwitch -Name HAWK-LAN -NetAdapterName "Ethernet" -AllowManagementOS $true
New-VMSwitch -Name HAWK-SEG-MT -SwitchType Private
New-VMSwitch -Name HAWK-SEG-OW -SwitchType Private
```

Con Wi-Fi, el switch externo funciona peor; si puedes, usa cable.

## 2. MikroTik CHR 7.x

### Crear la VM

1. Descarga la imagen VHDX de **Cloud Hosted Router**, rama 7 estable, desde
   la página de descargas de MikroTik y descomprímela, por ejemplo en
   `C:\HAWK\chr-7.vhdx`.
2. Crea la VM (Generación 1, que arranca la imagen sin tocar Secure Boot):
   ```powershell
   New-VM -Name hawk-mikrotik -Generation 1 -MemoryStartupBytes 256MB -VHDPath C:\HAWK\chr-7.vhdx -SwitchName HAWK-LAN
   Add-VMNetworkAdapter -VMName hawk-mikrotik -SwitchName HAWK-SEG-MT
   Set-VMProcessor -VMName hawk-mikrotik -Count 1
   Start-VM hawk-mikrotik
   ```
3. Abre la consola de la VM. El usuario es `admin` sin contraseña y pide
   crear una al entrar. `ether1` es la WAN (`HAWK-LAN`) y `ether2` la LAN.

### Configurar la red

```routeros
/ip address add address=192.168.88.31/24 interface=ether1
/ip route add gateway=192.168.88.1
/ip dns set servers=192.168.88.1
/ip address add address=10.23.1.1/24 interface=ether2
/ip pool add name=seg-mt ranges=10.23.1.10-10.23.1.50
/ip dhcp-server add name=seg-mt interface=ether2 address-pool=seg-mt disabled=no
/ip dhcp-server network add address=10.23.1.0/24 gateway=10.23.1.1 dns-server=192.168.88.1
# Internet para el agente sin enmascarar el tráfico hacia la LAN física (Core, Ollama)
/ip firewall nat add chain=srcnat out-interface=ether1 dst-address=!192.168.88.0/24 action=masquerade
```

### HTTPS para la API REST

```routeros
/certificate add name=hawk-ca common-name=hawk-ca key-usage=key-cert-sign,crl-sign
/certificate sign hawk-ca
/certificate add name=router common-name=192.168.88.31
/certificate sign router ca=hawk-ca
/ip service set www-ssl certificate=router disabled=no
/ip service set www disabled=yes
```

### Usuario del Core con permisos mínimos

```routeros
/user group add name=hawk policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!password,!sniff,!sensitive,!romon,!winbox,!web,!test
/user add name=hawk group=hawk password="<una contraseña larga>"
```

Revisa en la documentación de tu versión exacta de RouterOS que REST acepte
ese conjunto de políticas; si falla con 401 o 403, compara con la lista de
políticas que muestra `/user group print`.

### Lista y reglas de cuarentena (una sola vez)

```routeros
/ip firewall filter add chain=forward src-address-list=guardian_quarantine dst-address=192.168.88.20 action=accept comment="hawk: quarantined hosts may reach the Core"
/ip firewall filter add chain=forward src-address-list=guardian_quarantine action=drop comment="hawk: quarantine"
```

Muévelas al principio de la cadena `forward` si ya tienes otras reglas
(`/ip firewall filter print` y `move`). El Core solo agrega y quita
direcciones de la lista `guardian_quarantine`; las reglas no las toca.

## 3. OpenWrt x86/64

### Crear la VM

1. Descarga de la página de OpenWrt la imagen **x86/64
   `generic-ext4-combined.img.gz`** (la variante sin EFI, para Generación 1)
   de la versión 24.10.x o posterior, y descomprímela (con 7-Zip; un aviso de
   "datos sobrantes" al final es normal).
2. Conviértela a VHDX con `qemu-img` (paquete QEMU para Windows) y agrándala
   un poco:
   ```powershell
   qemu-img convert -f raw -O vhdx openwrt-x86-64-generic-ext4-combined.img C:\HAWK\openwrt.vhdx
   Resize-VHD -Path C:\HAWK\openwrt.vhdx -SizeBytes 1GB
   ```
3. Crea la VM:
   ```powershell
   New-VM -Name hawk-openwrt -Generation 1 -MemoryStartupBytes 256MB -VHDPath C:\HAWK\openwrt.vhdx -SwitchName HAWK-SEG-OW
   Add-VMNetworkAdapter -VMName hawk-openwrt -SwitchName HAWK-LAN
   Start-VM hawk-openwrt
   ```
   El primer adaptador queda como `eth0` (LAN) y el segundo como `eth1`
   (WAN), que es el orden que OpenWrt espera en x86.

### Configurar la red (consola de la VM)

```sh
passwd                                   # contraseña de root
uci set network.lan.ipaddr='10.23.2.1'
uci set network.wan.proto='static'
uci set network.wan.ipaddr='192.168.88.32'
uci set network.wan.netmask='255.255.255.0'
uci set network.wan.gateway='192.168.88.1'
uci add_list network.wan.dns='192.168.88.1'
uci commit network && /etc/init.d/network restart
```

Sin NAT hacia la LAN física (internet sí, enmascarado):

```sh
# La zona wan suele ser la segunda; compruébalo con: uci show firewall | grep zone
uci set firewall.@zone[1].masq='1'
uci add_list firewall.@zone[1].masq_dest='!192.168.88.0/24'
uci commit firewall && fw4 reload
```

Si tu versión no acepta la negación en `masq_dest`, desactiva `masq` en la
zona wan y el agente se queda sin internet (no lo necesita para la demo:
Ollama está en la LAN).

### Paquetes y acceso a ubus por HTTPS

```sh
apk update || opkg update                 # 24.10 usa opkg; versiones nuevas, apk
opkg install uhttpd uhttpd-mod-ubus rpcd luci-ssl   # o: apk add ...
/etc/init.d/uhttpd enable && /etc/init.d/uhttpd restart
```

`luci-ssl` crea un certificado autofirmado para `uhttpd`. Permite el acceso
HTTPS desde la LAN física (wan) solo a la IP del Core:

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='hawk-core-ubus'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].src_ip='192.168.88.20'
uci set firewall.@rule[-1].dest_port='443'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall && fw4 reload
```

### Instalar el plugin de HAWK

Copia los tres archivos de `integrations/openwrt/` (por `scp` desde la PC
anfitriona a `10.23.2.1`, o pegándolos en la consola):

```sh
# 1. El objeto ubus "guardian"
cp guardian /usr/libexec/rpcd/guardian && chmod 0755 /usr/libexec/rpcd/guardian
# 2. Su ACL: solo add, remove y list
cp guardian-acl.json /usr/share/rpcd/acl.d/guardian-acl.json
# 3. El set de nftables y la regla; reemplaza CORE_ADDRESS por la IP del Core
sed 's/CORE_ADDRESS/192.168.88.20/' guardian.nft > /etc/nftables.d/guardian.nft
fw4 reload && /etc/init.d/rpcd restart
ubus call guardian list                   # prueba local: devuelve el set vacío
```

### Usuario del Core en rpcd

```sh
uhttpd -m '<una contraseña larga>'        # imprime un hash $1$...
uci add rpcd login
uci set rpcd.@login[-1].username='hawk'
uci set rpcd.@login[-1].password='<el hash $1$... de arriba>'
uci add_list rpcd.@login[-1].read='guardian-core'
uci add_list rpcd.@login[-1].write='guardian-core'
uci commit rpcd && /etc/init.d/rpcd restart
```

Ese usuario solo puede iniciar sesión y llamar a `guardian add`, `remove` y
`list`: ni shell, ni `uci`.

## 4. La huella del certificado de cada router

El Core solo habla HTTPS con un router si conoce la huella SHA-256 de su
certificado. Desde cualquier máquina con OpenSSL en la LAN:

```sh
echo | openssl s_client -connect 192.168.88.31:443 2>/dev/null | openssl x509 -outform DER | sha256sum
echo | openssl s_client -connect 192.168.88.32:443 2>/dev/null | openssl x509 -outform DER | sha256sum
```

Es el valor que va en "Certificate SHA-256" del asistente de la app (o en
`MIKROTIK_CERT_SHA256` / `OPENWRT_CERT_SHA256`). Si regeneras el certificado
del router, la huella cambia y hay que actualizarla.

## 5. Las VMs de los agentes

En cada una (Ubuntu 24.04, red por DHCP de su router):

1. Instala OpenCode y copia `agent-hook/guardian.ts` a
   `~/.config/opencode/plugin/`.
2. Configura OpenCode para usar Ollama en la PC anfitriona
   (`http://<IP de la PC en la LAN>:11434`).
3. Copia el binario `host-daemon` (compílalo con `cargo build --release -p
   host-daemon` en la VM o cruzado) y córrelo como un usuario distinto del
   que usa el agente. Si el descubrimiento mDNS no cruza el router (es lo
   normal entre subredes), dale la dirección del Core:
   ```sh
   GUARDIAN_CORE=192.168.88.20:7443 ./host-daemon
   ```
4. Opcional: activa el TPM virtual de la VM (Hyper-V, Generación 2) para la
   futura atestación (ADR-0021); con Generación 1 no hay vTPM.

## 6. Configurar el Core y probar

1. Arranca el Core y actívalo con la app (asistente: Buscar, Verificar,
   Emparejar).
2. En el paso **Configurar**, primero elige **Dry run** y confirma que todo
   el flujo funciona sin tocar routers.
3. Después configura el router del segmento que vas a probar: tipo,
   `https://192.168.88.31` (o `.32`), usuario `hawk`, contraseña y huella.
   La configuración va firmada por el dueño y el Core la aplica al momento.
4. Verifica la cuarentena a mano desde el router antes de la demo:
   - MikroTik: `/ip firewall address-list print where list=guardian_quarantine`
   - OpenWrt: `ubus call guardian list` o `nft list set inet fw4 guardian_quarantine`
5. Con reglas de detección cargadas (pendiente del equipo), provoca un
   hallazgo crítico desde la VM del agente: la app debe mostrar el evento de
   contención, la IP del agente debe aparecer en la lista del router y la
   VM debe quedar sin red salvo hacia el Core.
6. Para liberar (hasta que exista el botón en la app): quita la dirección de
   la lista desde el router.

## Problemas comunes

| Síntoma | Causa probable |
|---|---|
| La app no encuentra el Core | El celular y la Pi en redes distintas, o multicast bloqueado (VLAN, red de invitados) |
| El daemon dice "no active core found" | mDNS no cruza el router: usa `GUARDIAN_CORE` |
| La cuarentena se aplica a la IP del router | Hay NAT entre el agente y el Core: revisa la regla de masquerade |
| El Core registra "containment failed" | Huella del certificado incorrecta, usuario sin permisos o reglas de firewall que no dejan llegar al puerto 443 |
| Las respuestas del modelo van muy lentas por el MikroTik | Licencia gratuita del CHR (1 Mbit/s): activa la prueba de 60 días |
