# PaxRadar v2.0.0

Detector experimental de dispositivos Wi-Fi mediante probe requests y
correlacion de huellas 802.11.

La version 2 requiere actualizar ambas partes:

1. Compilar y cargar `pax/pax.ino` en el ESP32.
2. Reiniciar `server.py`.

El servidor migra automaticamente `memoria_agente.json` del esquema 2 al 3.
Ese archivo contiene estado local de detecciones, se crea automaticamente y no
se versiona en Git.

## Pruebas

```bash
python3 -m unittest -v test_server.py
```
