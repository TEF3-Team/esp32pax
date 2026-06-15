# Changelog

## 2.0.1 - 2026-06-15

- Ignora el estado de ejecución local (memoria_agente.json, server.pid).
- Añade `.env.example` y actualiza `.gitignore`.

## 2.0.0 - 2026-06-15

- Agrega channel hopping en canales 1-13.
- Registra los canales donde se observa cada dispositivo.
- Mantiene historial y consenso de huellas.
- Endurece el matcher y evita asociaciones ambiguas.
- Confirma una MAC aleatoria nueva en dos barridos.
- Migra automaticamente la memoria del esquema 2 al 3.
- Agrega pruebas de regresion del fingerprint.
