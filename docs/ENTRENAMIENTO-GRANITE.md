# Entrenamiento del clasificador: complementar o afinar Granite

Guía para el equipo (en español, como `LAB.md` y `EJECUCION-PENDIENTES.md`).
Recomienda cómo construir la etapa de clasificación del ADR-0005: qué
entrenar, con qué datos, cómo medirlo y qué leer. Antes de entrenar con datos
de terceros hace falta el ADR de licencias de datos (ver "Licencias").

## Qué tiene que hacer el modelo

- **Entrada:** una tool call normalizada (herramienta, argumentos, directorio)
  y el contexto reciente de la sesión (las últimas N llamadas y decisiones).
- **Salida:** una severidad (`low`, `medium`, `high`, `critical`) y una razón
  corta. La política del ADR-0022 la convierte en permitir, preguntar,
  denegar o contener.
- **Dónde corre:** en el Core, una Raspberry Pi de 2 GB, junto a todo lo
  demás. Latencia objetivo: decenas de milisegundos por llamada.
- **Cuándo se usa:** solo cuando las reglas (la primera etapa) no deciden. No
  reemplaza a las reglas; cubre las variaciones que no anticiparon.

## Opciones, de la más barata a la más cara

| # | Opción | Esfuerzo | Cabe en la Pi | Cuándo elegirla |
|---|---|---|---|---|
| 1 | **Clasificador lineal propio** (hashing de rasgos + regresión logística), entrenado en la PC | Bajo | Sí, de sobra | Primero siempre: es la línea base del ADR-0014 y la vara contra la que se compara todo lo demás |
| 2 | **Granite sin entrenar**, con instrucciones y pocos ejemplos | Bajo | 350M cuantizado, justo | Para tener una segunda opinión rápida en casos ambiguos y medir cuánto aporta un LLM |
| 3 | **Granite afinado con LoRA** sobre tool calls etiquetadas | Medio | 350M cuantizado | Si la opción 1 se queda corta en el set de evaluación |
| 4 | **Destilación**: un modelo grande (Qwen 7B en la 4070, o un modelo por API) etiqueta muchos ejemplos y se afina Granite con esas etiquetas | Medio-alto | 350M cuantizado | Si faltan datos etiquetados a mano |

Recomendación: **1 → medir → 3 si hace falta**, usando 4 solo para ampliar
datos. Granite Guardian (de IBM, ver referencias) es útil como referencia de
diseño de un clasificador de riesgo, pero sus tamaños no caben en la Pi.

## Modelo base

- **IBM Granite**, licencia Apache-2.0 (permitida por el ADR-0011), en la
  organización `ibm-granite` de Hugging Face. Usar la variante más chica de
  la familia vigente (la clase de ~350M). Confirmar el nombre exacto del
  modelo y su licencia en su tarjeta antes de bajarlo.
- Nada de 1.5B o más en la Pi (ADR-0005).

## Datos

### Fuentes, en orden de prioridad

1. **El set de evaluación propio (M3, ADR-0010).** Es la fuente principal y la
   más limpia en licencia. Las tareas las escribe alguien distinto de quien
   escribe las reglas.
2. **Trazas reales del agente de prueba** (OpenCode + Ollama) haciendo tareas
   legítimas: dan el volumen de casos "permitir", que son la mayoría en la
   realidad.
3. **Benchmarks públicos de seguridad de agentes**, como fuente de *categorías*
   y escenarios (ver referencias: AgentDojo, InjecAgent, R-Judge, ToolEmu,
   AgentHarm). **Verificar la licencia de cada uno** antes de usar sus datos;
   varios tienen condiciones propias o piden no entrenar con ellos.
4. **Taxonomías** para etiquetar con consistencia: MITRE ATT&CK y MITRE
   ATLAS (técnica por ejemplo), OWASP Top 10 para aplicaciones con LLM.

### Formato sugerido

Una línea JSON por ejemplo: `tool`, `args`, `cwd`, `context` (las N
anteriores), `label` (severidad), `technique` (ATT&CK o ATLAS, si aplica),
`source` (eval, traza, benchmark, sintético) y `split`.

### Reglas para que la medición no mienta

- **Dividir por familia de tarea, no por ejemplo.** Si variaciones del mismo
  escenario quedan en entrenamiento y en prueba, la métrica sale inflada.
- **Desbalance:** en la realidad casi todo es "permitir". Medir con
  precisión/recuperación por clase, no con exactitud.
- **Ataques compuestos** (varios pasos inocentes que juntos dañan) en un
  grupo aparte: es la debilidad conocida de un monitor chico, y se reporta.
- **Los datos de ataque viven en el repositorio privado**, describen
  categorías y objetivos, y apuntan solo al sandbox.

## Receta de afinado (opción 3)

Herramientas, todas con licencia permitida: Hugging Face `transformers`,
`peft` y `trl` (Apache-2.0); opcionalmente Unsloth (Apache-2.0) para entrenar
más rápido en la 4070.

1. Plantilla de entrada fija (la tool call y el contexto en un formato
   estable) y salida corta: la etiqueta y la razón.
2. LoRA sobre las capas de atención; con ~350M parámetros incluso cabe un
   afinado completo en 12 GB de VRAM, pero LoRA deja adaptadores pequeños y
   fáciles de versionar.
3. Pocas épocas y parada temprana con el conjunto de validación; vigilar que
   no aprenda a "denegar todo" (los falsos positivos cuestan uso real).
4. **Calibración:** elegir los umbrales de `medium` (preguntar) y `high`
   (denegar) con la curva de validación, no a ojo.
5. Exportar a GGUF y cuantizar (Q8 y Q4) con llama.cpp; medir en la Pi real la
   memoria, la latencia y la caída de calidad de cada cuantización.
6. Comparar contra la opción 1 en las métricas del ADR-0010: seguridad,
   falsos positivos, utilidad y latencia, para "sin Core", "solo reglas",
   "reglas + lineal" y "reglas + Granite".

## Licencias (antes de entrenar)

Hace falta un ADR que diga qué datos se pueden usar para entrenar, porque
el ADR-0011 cubre código y modelos, no datos de entrenamiento:

- Material CC-BY-SA (por ejemplo OWASP): el *share-alike* puede alcanzar a los
  pesos derivados; usarlo como referencia para etiquetar, no como datos.
- arXiv: cada paper tiene su propia licencia; usar las ideas, no copiar texto.
- MITRE ATT&CK y ATLAS: términos de uso propios; citar los identificadores es
  lo habitual.
- Benchmarks: cada uno con su licencia y, a veces, con la petición explícita de
  no entrenar con su conjunto de prueba.

## Lecturas

### AI control y monitoreo de agentes

- Greenblatt, Shlegeris et al., *AI Control: Improving Safety Despite
  Intentional Subversion*, 2023. [arXiv:2312.06942](https://arxiv.org/abs/2312.06942)
- Redwood Research, *The Case for AI Control*, 2024 (blog de Redwood).
- Bhatt et al., *Ctrl-Z: Controlling AI Agents via Resampling*, 2025.
  [arXiv:2504.10374](https://arxiv.org/abs/2504.10374)
- Kutasov et al., *SHADE-Arena: Evaluating Sabotage and Monitoring in LLM
  Agents*, 2025. [arXiv:2506.15740](https://arxiv.org/abs/2506.15740)
- Benton et al., *Sabotage Evaluations for Frontier Models*, 2024.
  [arXiv:2410.21514](https://arxiv.org/abs/2410.21514)
- Baker et al., *Monitoring Reasoning Models for Misbehavior and the Risks of
  Promoting Obfuscation*, 2025. [arXiv:2503.11926](https://arxiv.org/abs/2503.11926)
- UK AI Security Institute, **ControlArena** (GitHub
  `UKGovernmentBEIS/control-arena`) e **Inspect** (inspect.aisi.org.uk).

### Inyección de prompts y seguridad de agentes con herramientas

- Greshake et al., *Not What You've Signed Up For: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection*, 2023.
  [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)
- Debenedetti et al., *AgentDojo*, 2024. [arXiv:2406.13352](https://arxiv.org/abs/2406.13352)
- Zhan et al., *InjecAgent*, 2024. [arXiv:2403.02691](https://arxiv.org/abs/2403.02691)
- Ruan et al., *Identifying the Risks of LM Agents with an LM-Emulated
  Sandbox* (ToolEmu), 2023. [arXiv:2309.15817](https://arxiv.org/abs/2309.15817)
- Yuan et al., *R-Judge: Benchmarking Safety Risk Awareness for LLM Agents*,
  2024. [arXiv:2401.10019](https://arxiv.org/abs/2401.10019)
- Andriushchenko et al., *AgentHarm*, 2024. [arXiv:2410.09024](https://arxiv.org/abs/2410.09024)

### Clasificadores de riesgo (como referencia de diseño)

- Padhi et al., *Granite Guardian*, IBM, 2024. [arXiv:2412.07724](https://arxiv.org/abs/2412.07724)
- Inan et al., *Llama Guard*, 2023. [arXiv:2312.06674](https://arxiv.org/abs/2312.06674)
  (su licencia de modelo no es compatible con el ADR-0011; leer el paper, no
  usar los pesos).

### Afinado eficiente

- Hu et al., *LoRA: Low-Rank Adaptation of Large Language Models*, 2021.
  [arXiv:2106.09685](https://arxiv.org/abs/2106.09685)
- Dettmers et al., *QLoRA*, 2023. [arXiv:2305.14314](https://arxiv.org/abs/2305.14314)
- Rafailov et al., *Direct Preference Optimization*, 2023.
  [arXiv:2305.18290](https://arxiv.org/abs/2305.18290) (si más adelante se
  quiere afinar con preferencias "mejor denegar esto que aquello").

### Taxonomías y marcos

- MITRE ATT&CK (attack.mitre.org) y MITRE ATLAS (atlas.mitre.org).
- OWASP Top 10 for LLM Applications (genai.owasp.org), CC-BY-SA.
- NIST AI Risk Management Framework y su perfil de IA generativa
  (NIST AI 600-1).
- Reglas por defecto de Falco (`falcosecurity/rules`, Apache-2.0): ideas de
  detección por comportamiento en sistemas Linux.

### Libros

- Chip Huyen, *AI Engineering*, O'Reilly, 2025.
- Chip Huyen, *Designing Machine Learning Systems*, O'Reilly, 2022.
- Jay Alammar y Maarten Grootendorst, *Hands-On Large Language Models*,
  O'Reilly, 2024.
- Sebastian Raschka, *Build a Large Language Model (From Scratch)*, Manning,
  2024.
- Clarence Chio y David Freeman, *Machine Learning and Security*, O'Reilly,
  2018.

### Documentación de herramientas

- Hugging Face: `transformers`, `peft`, `trl` (huggingface.co/docs).
- llama.cpp: conversión a GGUF y cuantización (github.com/ggml-org/llama.cpp).
- Ollama: Modelfile y `num_ctx` (para el agente de prueba, ADR-0009).
- IBM Granite: tarjetas de modelo en huggingface.co/ibm-granite.

## Criterio de terminado

- La tabla de métricas del ADR-0010 con la opción 1 y, si se entrenó, la 3.
- El modelo cuantizado medido en la Pi (memoria y latencia) dentro del
  presupuesto del ADR-0005.
- El ADR de licencias de datos aprobado y los datos usados listados con su
  origen.
