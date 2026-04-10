# Environment Matrix and Parity

- Python: 3.11.x (local venv: aods_venv)
- Node: 18.x (UI dev/build)
- OS: Linux/WSL2 parity; prefer Linux paths and UTF-8

UI modes
- Dev: Vite dev; not used for promotion gates
- Preview /ui (mock): smoke acceptance (4 pass, 0 skip); for local checks
- API-served /ui (prod-shell): required for promotion; run `scripts/run_e2e_prod.sh`
