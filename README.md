# Forensic Tool

A comprehensive digital forensic analysis tool written in Python with a GUI interface.

## Features

# Forensic Tool — Final Project (Computer Forensics)

This repository contains a lightweight real-time process threat monitor implemented in Python with a Tkinter GUI.

Purpose: final project for a Computer Forensics course — demonstrates live process enumeration, basic heuristics for suspicious process detection, and optional VirusTotal integration.

Highlights

- Real-time monitoring of system processes
- Heuristics for suspicious activity (keyword matching, suspicious ports, short runtime, memory spikes, fileless processes)
- VirusTotal lookups (optional; requires `VIRUSTOTAL_API_KEY` environment variable)

Quick start

1. Install Python 3.8+.
2. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. (Optional) Set VirusTotal API key to enable file hash lookups:

```powershell
$env:VIRUSTOTAL_API_KEY = 'your_api_key_here'
```

5. Run the GUI:

```powershell
python src\threat_monitor.py
```

Recommended (easier) workflow on Windows

- Copy `example.env` to `.env` and edit to add your real key locally (do not commit `.env`).
- Then run the app directly which will read `.env` automatically at startup:

```powershell
python src\threat_monitor.py
```

Notes

- The project is provided as-is for educational purposes.
- Do not embed API keys in source. Use environment variables as shown above.

License

MIT
