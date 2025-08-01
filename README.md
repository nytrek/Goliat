<p align="center">
  <img src="goliat.png" alt="Logo de GOLIAT" width="600"/>
</p>

<h1 align="center">🔐 GOLIAT – Sistema Avanzado de Contraseñas con IA</h1>

<p align="center">
  <b>Gestión. Seguridad. Inteligencia. Todo en uno.</b><br>
  Análisis, generación y protección de contraseñas como nunca antes.
</p>

<p align="center">
  <a href="https://github.com/nytrek/goliat">
    <img src="https://img.shields.io/github/stars/nytrek/goliat?style=social" alt="GitHub stars"/>
  </a>
  <a href="https://github.com/nytrek/goliat">
    <img src="https://img.shields.io/github/license/nytrek/goliat?style=flat-square" alt="License"/>
  </a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Rich%20UI-CLI%20Power-blueviolet?style=flat-square"/>
</p>

---

## 🚀 ¿Qué es GOLIAT?

GOLIAT es un sistema ultra-avanzado para analizar y generar contraseñas seguras usando técnicas de inteligencia artificial heurística. Pensado para ciberseguridad real, ofrece evaluaciones inteligentes, análisis de brechas, generación de contraseñas personalizadas y una interfaz de consola visual y profesional.

---

## 🧠 Características

- 🔍 Análisis IA de contraseñas (entropía, patrones, teclado, fechas, leet speak, etc.)
- 🚨 Verificación de brechas con la API de [Have I Been Pwned](https://haveibeenpwned.com/)
- 🔐 Generación avanzada: criptográfica, pronunciable, frase, patrón
- 📊 Visualización avanzada con [Rich](https://github.com/Textualize/rich)
- 📈 Estadísticas, puntuación, tiempo de crackeo, recomendaciones
- 💾 Exportación a JSON, CSV, TXT
- 🔒 Historial y base de datos local en SQLite

---

## 🖼️ Capturas de pantalla

### 🏠 Menú principal
![Menú principal](assets/captura%20de%20pantalla%201.png)

### 📊 Análisis de contraseña
![Análisis avanzado](assets/captura%20de%20pantalla%202.png)

---

## 📦 Instalación

### Requisitos
- Python 3.9 o superior
- `pip`

### Instalar y ejecutar

```bash
git clone https://github.com/nytrek/goliat.git
cd goliat
pip install -r requirements.txt
python goliat.py
