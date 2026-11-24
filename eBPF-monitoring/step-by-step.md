# eBPF network monitor (versión C): paso a paso

Notas para entender cómo funciona `initial-application-c`, desde el código fuente hasta que el kernel ejecuta el programa eBPF con cada paquete.

1. [Del código al ejecutable: Makefile, ELF y skeleton](#1-del-código-al-ejecutable-makefile-elf-y-skeleton)
2. [El map `l3protos_stats`](#2-el-map-l3protos_stats)
3. [El flujo del programa: open → load → attach](#3-el-flujo-del-programa-open--load--attach)
4. [¿En qué momento el programa eBPF coge cada paquete?](#4-en-qué-momento-el-programa-ebpf-coge-cada-paquete)
5. [¿Qué cuenta exactamente el map?](#5-qué-cuenta-exactamente-el-map)
6. [Limpieza](#6-limpieza)
7. [Comprobar todo con comandos](#7-comprobar-todo-con-comandos)
8. [¿libbpf o bpftool? Se usan los dos](#8-libbpf-o-bpftool-se-usan-los-dos)

---

## 1. Del código al ejecutable: Makefile, ELF y skeleton

### Qué hace el Makefile
El [Makefile](initial-application-c/Makefile) automatiza los pasos 5, 6 y 7 del README. Cada regla tiene esta forma:

```make
objetivo: dependencias
	comando para construir el objetivo
```

En este proyecto hay tres reglas encadenadas, más `clean`:

| Objetivo | Depende de | Comando | Qué produce |
|---|---|---|---|
| `network_monitor.bpf.o` | `network_monitor.bpf.c`, `network_monitor.h` | `clang -g -O2 -target bpf -c ...` | Bytecode eBPF (archivo ELF) |
| `network_monitor.skel.h` | `network_monitor.bpf.o` | `bpftool gen skeleton ...` | Header C generado (el skeleton) |
| `network_monitor` | `network_monitor.c`, `network_monitor.h`, `network_monitor.skel.h` | `gcc ... -lbpf` | El ejecutable final (user space) |
| `clean` | nada | `rm -f ...` | Borra los tres archivos generados |

Cuando ejecutas `make` sin argumentos:
1. Construye el **primer objetivo** del archivo, `network_monitor`.
2. Antes revisa sus dependencias, y las dependencias de esas, hacia atrás.
3. Solo reconstruye un archivo si **alguna dependencia es más reciente** que él (compara fechas de modificación).

Por eso a veces aparece `make: 'network_monitor' is up to date.`: no ha cambiado nada y no hay nada que hacer. Para compilar todo desde cero: `make clean && make`.

### Qué es ELF
**ELF** (*Executable and Linkable Format*) es el formato estándar de Linux para ejecutables, archivos objeto (`.o`) y librerías (`.so`). Un `.bpf.o` es un ELF normal, con una diferencia: su "máquina" es **BPF** y no x86. El código no es para tu CPU, sino para la máquina virtual eBPF del kernel.

Un ELF está dividido en **secciones**, y la macro `SEC("...")` decide en cuál va cada cosa:

| En el código | Sección del ELF |
|---|---|
| `SEC("tc") int tc_prog(...)` | `tc` (el bytecode del programa) |
| `struct {...} l3protos_stats SEC(".maps")` | `.maps` (la descripción del map) |
| `char __license[] SEC("license")` | `license` |
| (generado por `-g`) | `.BTF` (información de tipos) |

Para verlo:
```sh
llvm-objdump -h initial-application-c/network_monitor.bpf.o
```

libbpf lee estas secciones para saber qué programas y qué maps hay, y a qué tipo de hook va cada programa (`tc`).

### Qué es el skeleton
`bpftool gen skeleton` lee el `.bpf.o` y genera [network_monitor.skel.h](initial-application-c/network_monitor.skel.h), que contiene dos cosas:

**a) El `.bpf.o` completo, metido como bytes dentro del header:**
```c
static inline const void *network_monitor_bpf__elf_bytes(size_t *sz)
{
	*sz = 12688;
	return (const void *)"\x7f\x45\x4c\x46..."   // ← "\x7f E L F": el .bpf.o entero
```
Por eso el ejecutable `network_monitor` ya lleva dentro el programa eBPF y no necesita buscar el `.o` en disco.

**b) Una struct con acceso por nombre a los programas y maps:**
```c
struct network_monitor_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *l3protos_stats;   // ← tu map, con el mismo nombre
		struct bpf_map *rodata;           // ← constantes (p. ej. el texto de bpf_printk)
	} maps;
	struct {
		struct bpf_program *tc_prog;      // ← tu función SEC("tc")
	} progs;
	struct {
		struct bpf_link *tc_prog;
	} links;
};
```

**Resumen:** el skeleton es código generado que lleva dentro el `.o` y te da acceso con nombre a sus programas y maps.

### Así se conecta todo
```
network_monitor.bpf.c ──clang -target bpf──► network_monitor.bpf.o ──bpftool gen skeleton──► network_monitor.skel.h
   (tu código eBPF)                           (bytecode eBPF, ELF)                             (código C generado)
                                                                                                      │
network_monitor.c  ── #include "network_monitor.skel.h" ◄─────────────────────────────────────────────┘
        │
        └──gcc -lbpf──► network_monitor   (ejecutable que lleva dentro el programa eBPF)
```

El `main` sabe cuál es el programa eBPF porque **se decide al compilar**: incluye el skeleton, y el skeleton lleva dentro el `.bpf.o`.

### Reglas de nombres del skeleton (siempre las mismas)

| En tu código eBPF | En el skeleton |
|---|---|
| Archivo `network_monitor.bpf.o` | `struct network_monitor_bpf` y funciones `network_monitor_bpf__open()`, `__load()`, `__open_and_load()`, `__attach()`, `__destroy()` |
| Función `SEC("...") int tc_prog(...)` | `skel->progs.tc_prog` y `skel->links.tc_prog` |
| Map `struct {...} l3protos_stats SEC(".maps")` | `skel->maps.l3protos_stats` |
| Variable global `int contador;` (sin inicializar) | `skel->bss->contador` |
| Variable global `int x = 5;` (inicializada) | `skel->data->x` |
| Variable global `const volatile int y = 5;` | `skel->rodata->y` (se puede cambiar entre open y load) |

- El nombre de la struct sale del nombre del archivo: `network_monitor.bpf` → `network_monitor_bpf`.
- Si renombras la función o el map en el `.bpf.c`, el skeleton se regenera con `make` y tienes que usar el nombre nuevo en `network_monitor.c`. Si no lo cambias, gcc da error de compilación, lo cual es útil para detectar el problema.

---

## 2. El map `l3protos_stats`

```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, struct l3proto_stats);
} l3protos_stats SEC(".maps");
```

### Qué significa cada línea
| Línea | Significado |
|---|---|
| `type = BPF_MAP_TYPE_HASH` | Es un hash map: se busca por key, no por posición |
| `max_entries = 1024` | Como máximo 1024 keys distintas |
| `key = __u16` | La key ocupa **2 bytes** porque el campo EtherType de Ethernet mide 2 bytes. El comentario "*the size of the ethertype*" habla del **tipo/tamaño** de la key, no de su valor |
| `value = struct l3proto_stats` | Cada value es `{ pkts, bytes }` (2 × 8 bytes) |

### Dibujo del map
No es una lista con índices 0, 1, 2… En un hash map **la key es lo que se busca**. El kernel aplica internamente una función hash a la key para saber dónde guardarla, pero eso no lo ves.

```
          l3protos_stats  (BPF_MAP_TYPE_HASH, max_entries = 1024)

        KEY (__u16, 2 bytes)              VALUE (struct l3proto_stats, 16 bytes)
     ┌───────────────────────┐        ┌──────────────────┬──────────────────┐
     │ 0x0800  (IPv4)        │ ─────► │ pkts  = 42       │ bytes = 5120     │
     ├───────────────────────┤        ├──────────────────┼──────────────────┤
     │ 0x0806  (ARP)         │ ─────► │ pkts  = 3        │ bytes = 126      │
     ├───────────────────────┤        ├──────────────────┼──────────────────┤
     │ 0x86DD  (IPv6)        │ ─────► │ pkts  = 7        │ bytes = 860      │
     └───────────────────────┘        └──────────────────┴──────────────────┘

     Solo existen las entradas de los protocolos que se han visto.
```

### `l3protos_stats` vs `l3proto_stats` (solo cambia una "s")
| Nombre | Qué es | Dónde |
|---|---|---|
| `l3protos_stats` (plural) | **Nombre de la variable**: el map completo, con las stats de *todos* los protocolos | [network_monitor.bpf.c](initial-application-c/network_monitor.bpf.c) |
| `struct l3proto_stats` (singular) | **Tipo de cada value**: las stats de *un* protocolo | [network_monitor.h](initial-application-c/network_monitor.h) |

La struct del map es **anónima** (`struct { ... } nombre;`), igual que en este ejemplo:
```c
struct { int x; int y; } punto;   // "punto" es una variable, la struct no tiene nombre
```

`__uint` y `__type` son macros de libbpf que **describen** el map. `SEC(".maps")` lo coloca en la sección `.maps` del ELF, y al cargar libbpf le pide al kernel que cree un map con esas características.

### Orden de bytes: `bpf_ntohs(key)`
La key se guarda **tal cual viene en el paquete**, en orden de red (*big-endian*). Tu CPU x86 es *little-endian* y lee esos 2 bytes al revés:

```
En el paquete (IPv4):   08 00
Leído como __u16 en x86:  key = 0x0008      ← no coincide con ETH_P_IP (0x0800)
bpf_ntohs(0x0008)    →  0x0800           ← ahora sí → "IPv4"
```

- `ntohs` = **n**etwork **to** **h**ost **s**hort (16 bits).
- La función inversa es `bpf_htons()`. Se usa en el programa eBPF para comparar con constantes, por ejemplo `eth->h_proto == bpf_htons(ETH_P_IP)`.

---

## 3. El flujo del programa: open → load → attach

### Funciones auxiliares (antes del `main`)
| Función | Qué hace |
|---|---|
| `ethtype_to_proto(ethtype)` | Recibe el EtherType **ya convertido** a orden de host y devuelve un texto (`"IPv4"`, `"ARP"`, `"IPv6"`, `"Unknown"`) para imprimirlo |
| `dump_l3protos_map(map)` | Recorre todas las keys del map (`bpf_map__get_next_key`), lee cada value (`bpf_map__lookup_elem`) e imprime los totales |

### El `main`
| Fase | Código | Qué pasa |
|---|---|---|
| **open** | `network_monitor_bpf__open()` | libbpf lee los bytes ELF embebidos y encuentra el programa `tc_prog` y el map `l3protos_stats`. **Todavía no ha pasado nada en el kernel.** |
| **load** | `network_monitor_bpf__load()` | Llama a la syscall `bpf()`: **crea el map** en el kernel y **carga el programa**. Aquí actúa el **verifier**: si falta un chequeo de límites, el programa se rechaza. Si lo acepta, el kernel lo compila a código máquina (JIT). |
| **crear hook** | `bpf_tc_hook_create(&tc_hook_ingress)` | Crea la qdisc `clsact` en la interfaz (equivale a `tc qdisc add dev eth0 clsact`). Una sola qdisc sirve para ingress y egress. |
| **attach** | `bpf_tc_attach(...)` × 2 | Engancha el programa (`.prog_fd = bpf_program__fd(skel->progs.tc_prog)`) como filtro en ingress y en egress. |
| **bucle** | `while (!stop) { sleep(1); dump...; }` | Cada segundo lee el map e imprime los totales. Ctrl+C pone `stop = 1`. |
| **limpieza** | `bpf_tc_hook_destroy` + `network_monitor_bpf__destroy` | Ver sección 6. |

`network_monitor_bpf__open_and_load()` no es más que open + load seguidos.

### Load ≠ attach
- En el **load**, el programa se **inyecta** en el kernel. Ya está dentro, pero **no se ejecuta nunca** porque no está enganchado a nada.
- En el **attach**, le dices al kernel: *"cada vez que pase un paquete por aquí, ejecuta este programa"*.

Para TC el attach se hace a mano y no con `network_monitor_bpf__attach()` del skeleton. libbpf no puede hacerlo solo porque necesita saber **en qué interfaz** (`ifindex`) y **en qué lado** (ingress/egress).

---

## 4. ¿En qué momento el programa eBPF coge cada paquete?

**Desde que termina `bpf_tc_attach`.** Lo hace el **kernel**, no tu `main`. Nadie en `network_monitor.c` llama a `tc_prog()`; la llama el subsistema TC del kernel.

Hay dos mundos que se ejecutan en paralelo y que solo se comunican a través del **map**:

```
 ════════════════ KERNEL ═════════════════════        ══════════ USER SPACE (tu main) ══════════

 paquete llega a eth0                                   while (!stop) {
        │                                                   sleep(1);
        ▼                                                   dump_l3protos_map(...)
 driver de red                                                   │
        │                                                        │ bpf_map__get_next_key
        ▼                                                        │ bpf_map__lookup_elem
 TC ingress hook ──► el kernel LLAMA a tc_prog(ctx)              │ (syscalls bpf())
                         │                                       │
                         │  lookup / update / +1                 ▼
                         └──────────────►  ┌────────────────────────┐
                                           │  map l3protos_stats    │  ◄── memoria del kernel,
                         ┌──────────────►  │  0x0800 → {pkts,bytes} │      la comparten ambos
                         │                 └────────────────────────┘
 TC egress hook  ──► el kernel LLAMA a tc_prog(ctx)                       printf("Proto IPv4: ...")
        ▲                                                   }
 paquete que sale de eth0
```

- Por **cada paquete**, el kernel ejecuta `tc_prog`. Si llegan 1000 paquetes en un segundo, `tc_prog` se ejecuta 1000 veces, y puede hacerlo en varios núcleos a la vez. Por eso usa `__sync_fetch_and_add` (suma atómica).
- El `main` pasa casi todo el tiempo dormido en `sleep(1)`. Cada segundo despierta, **lee** el map e imprime.
- El programa eBPF **escribe** en el map y el `main` lo **lee**.
- Quien imprime **cada paquete** es `bpf_printk` dentro de `tc_prog`, y lo hace en `/sys/kernel/debug/tracing/trace_pipe`, no en tu terminal.

### Qué hace `tc_prog` con cada paquete
```
tc_prog(ctx)
  │
  ├─ data, data_end = inicio y fin del paquete
  ├─ ¿cabe una cabecera Ethernet?  ── no ──► TC_ACT_SHOT (descarta el paquete)
  │
  ├─ val = lookup(map, eth->h_proto)
  ├─ ¿val == NULL? (primer paquete de este protocolo)
  │     └─ sí ──► update(map, key, {0,0}, BPF_NOEXIST) y lookup otra vez
  │
  ├─ val->pkts  += 1                 (atómico)
  ├─ val->bytes += data_end - data   (atómico)
  ├─ bpf_printk("Processed packet with l3proto 0x%04x")
  └─ return TC_ACT_OK  ──► el paquete sigue su camino normal
```

---

## 5. ¿Qué cuenta exactamente el map?

- Los contadores son **acumulados desde que arrancó el programa**, no "lo de este segundo". El map nunca se pone a cero: cada segundo el `main` muestra **el total hasta ese momento**.
  - Para ver paquetes por segundo habría que restar el valor anterior al actual en user space, o borrar las entradas después de leerlas.
- Ingress y egress usan **el mismo programa y el mismo map**, así que cada contador suma los paquetes que **entran y salen**.
- `max_entries = 1024` es el máximo de **protocolos distintos** (keys). En la práctica solo aparecen unos pocos (IPv4, IPv6, ARP…). Si el map se llenara, `bpf_map_update_elem` fallaría y el paquete pasaría sin contarse.
- Detalle: `data_end - data` es la parte del paquete accesible directamente (parte *lineal*). En paquetes grandes puede ser menor que el tamaño real, que está en `ctx->len`.

---

## 6. Limpieza

| Código | Qué hace |
|---|---|
| `bpf_tc_hook_destroy(...)` | Quita la qdisc `clsact` de la interfaz, y con ella los filtros. El kernel deja de llamar a `tc_prog`. |
| `network_monitor_bpf__destroy(skel)` | Cierra los descriptores del programa y del map, y el kernel los libera. |

---

## 7. Comprobar todo con comandos

Con `sudo ./network_monitor eth0` corriendo, en otra terminal de WSL:

```sh
sudo bpftool prog show name tc_prog              # el programa está cargado en el kernel (load)
sudo tc filter show dev eth0 ingress             # está enganchado al hook ingress (attach)
sudo tc filter show dev eth0 egress              # y al egress
sudo bpftool map dump name l3protos_stats        # contenido del map visto desde fuera
sudo cat /sys/kernel/debug/tracing/trace_pipe    # una línea por paquete (bpf_printk)
```

Si detienes el programa (Ctrl+C) y repites los dos primeros comandos, el programa y los filtros ya no aparecen.

---

## 8. ¿libbpf o bpftool? Se usan los dos

Tienen papeles distintos. **libbpf** es una librería que se ejecuta dentro de tu programa. **bpftool** es una herramienta de línea de comandos que usas al compilar y al depurar.

| | **libbpf** | **bpftool** |
|---|---|---|
| Qué es | Una **librería de C** | Un **programa de línea de comandos** (construido sobre libbpf) |
| Cuándo se usa | **Cada vez que se ejecuta `network_monitor`** | **Al compilar**, y cuando quieres inspeccionar algo a mano |
| Cómo entra al proyecto | Se enlaza con `gcc ... -lbpf`; headers `#include <bpf/...>` | El Makefile la llama: `bpftool gen skeleton` |
| ¿Hace falta para ejecutar? | **Sí** (`libbpf.so`) | **No** |

### Dónde aparece libbpf
- **En `network_monitor.c` (user space):**
  - abrir y cargar: `__open_and_load()` del skeleton llama por dentro a `bpf_object__open_skeleton` y `bpf_object__load_skeleton` de libbpf
  - enganchar: `bpf_tc_hook_create`, `bpf_tc_attach`, `bpf_program__fd`, `LIBBPF_OPTS`
  - leer el map: `bpf_map__get_next_key`, `bpf_map__lookup_elem`

  Todas acaban en llamadas a la syscall `bpf()`.
- **En `network_monitor.bpf.c` (código eBPF):** solo se usan sus **headers**.
  - `bpf_helpers.h`: `SEC()`, `__uint`, `__type`, `bpf_printk`
  - `bpf_endian.h`: `bpf_ntohs`

  `bpf_map_lookup_elem` está declarada en `bpf_helpers.h`, pero es un *helper* que implementa el **kernel**. El código de libbpf no se ejecuta dentro del kernel.

### Dónde aparece bpftool
- En el Makefile: `bpftool gen skeleton network_monitor.bpf.o > network_monitor.skel.h` genera el skeleton.
- Para depurar a mano: `bpftool prog show`, `bpftool map show`, `bpftool map dump name l3protos_stats`.

El skeleton es "una alternativa a la API genérica de libbpf" (README). Es una capa de comodidad que genera bpftool, pero su código sigue llamando a libbpf por debajo.

```
COMPILACIÓN                                      EJECUCIÓN
───────────                                      ─────────
.bpf.c ──clang──► .bpf.o ──bpftool──► .skel.h    ./network_monitor
                                         │            │
network_monitor.c ──gcc -lbpf────────────┘            ├─ libbpf ──bpf() syscall──► kernel
                                                      │    (load, attach, leer map)
                                                      └─ (bpftool no participa)
```
