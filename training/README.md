# training

El pipeline del clasificador de HAWK (M10, ADR-0005), según
[`docs/ENTRENAMIENTO-GRANITE.md`](../docs/ENTRENAMIENTO-GRANITE.md). En el
Core corren las reglas y este clasificador; el modelo del agente (Qwen,
Claude, Codex) corre en la PC del agente, nunca en el Core.

- **Estado:** pipeline listo para correr en la PC de la RTX 4070. Falta lo que
  tiene que poner el equipo: datos etiquetados (hoy solo están los ~50
  ejemplos del catálogo de reglas) y la aprobación del ADR-0035 (licencias
  de datos). El uso del modelo dentro del Core (cargarlo en `detect`) no
  está construido.

## Preparar la PC de entrenamiento (la de la 4070)

```sh
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
# PyTorch con CUDA, según https://pytorch.org/get-started/locally/
pip install -r training/requirements.txt
```

## Los pasos, en orden

| # | Comando | Qué hace | Necesita GPU |
|---|---|---|---|
| 0 | `python training/import_tldr.py <clon de tldr-pages>` | Convierte los ejemplos de tldr-pages en llamadas `low` (`data/tldr.jsonl`); lo sensible o lo que dispara una regla va a `out/tldr-review.jsonl` para etiquetar a mano | No |
| 1 | `python training/prepare.py` | Junta los ejemplos del catálogo y `training/data/*.jsonl`, los valida, quita duplicados y divide por familia (70/15/15) en `training/out/dataset/` | No |
| 2 | `python training/baseline_linear.py` | Opción 1: hashing + regresión logística. La línea base contra la que se compara todo; exporta los pesos en `out/linear/model.json` | No |
| 3 | `python training/train_lora.py --zero-shot` | Opción 2: Granite sin entrenar, para saber cuánto aporta un LLM | Recomendable |
| 4 | `python training/train_lora.py` | Opción 3: Granite afinado con LoRA; adaptador en `out/lora/adapter` | Sí |
| 5 | `python training/evaluate.py <predicciones.jsonl>` | Las métricas de cualquier archivo con `label` y `pred` | No |

El modelo es **Granite 4 de unos 800M** de
[huggingface.co/ibm-granite](https://huggingface.co/ibm-granite): poner su id
en `training/config.json` después de confirmar en la tarjeta el tamaño y la
licencia (Apache-2.0). `train_lora.py` cuenta los parámetros y se niega con
1.5B o más (ADR-0005). `--model <id>` lo cambia para una corrida.

Cada paso imprime, para `val` y `test`: precisión y recuperación por clase,
la **tasa de falsas alarmas** (llamadas legítimas que el modelo preguntaría o
negaría) y la **tasa de fallos** (llamadas `high` o `critical` que dejaría
pasar como `low`). Elegir el modelo por esas dos, no por la exactitud.

## Datos

Un ejemplo por línea en `training/data/<nombre>.jsonl`; el formato está en
`common.py`. Lo mínimo:

```json
{"tool": "bash", "args": {"command": "npm test"}, "cwd": "/work", "label": "low", "family": "tests-run", "source": "trace"}
```

- `label`: `low`, `medium`, `high` o `critical` (la política del ADR-0022 la
  convierte en permitir, preguntar, negar o aislar).
- `family`: el escenario. Las variaciones de un mismo escenario comparten
  familia, así nunca quedan una en entrenamiento y otra en prueba.
- `source`: tiene que estar en [`data/SOURCES.md`](data/SOURCES.md) (ADR-0035);
  `prepare.py` rechaza cualquier otra.
- La mayoría de los ejemplos reales son legítimos (`low`): hacen falta muchos,
  sacados de trazas del agente haciendo trabajo normal en el laboratorio.
  `import_tldr.py` da ~9 400 de tldr-pages (`git clone --depth 1
  https://github.com/tldr-pages/tldr`); las etiquetas de lo sensible las pone
  el equipo, nunca se copian de las reglas (copiarían sus falsos positivos).
- Lo que falta son ejemplos peligrosos: `train_lora.py` repite los que no son
  `low` hasta ser `risky_share` del entrenamiento (`config.json`), pero
  repetir 25 ejemplos no enseña familias nuevas.

## Después de entrenar

1. Exportar a GGUF y cuantizar (Q8 y Q4) con llama.cpp:
   `convert_hf_to_gguf.py` sobre el modelo con el adaptador fusionado, luego
   `llama-quantize`.
2. Medir en el Core real (la Pi o el equipo dedicado): memoria, latencia por
   decisión y caída de calidad de cada cuantización.
3. Comparar contra la línea base lineal en las métricas del ADR-0010 antes
   de llevarlo al Core.

## Lo que nunca debe hacer

- Entrenar con una fuente que no esté en `data/SOURCES.md`.
- Mezclar familias entre entrenamiento y prueba.
- Elegir un modelo que "niega todo": las falsas alarmas cuestan uso real.
