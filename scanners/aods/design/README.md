# AODS Design Assets

This folder contains design mockups and the production React frontend for the AODS web interface.

## Folder Structure

```
design/
├── README.md                           # This file
└── ui/                                 # UI assets and React app
    ├── index.html                      # Static mockup showcase
    ├── mockup_ui.html                  # Interactive readiness mockup
    ├── MD3_Dashboard.svg               # Dashboard mockup
    ├── MD3_Scans.svg                   # Scan management mockup
    ├── MD3_Results_Explorer.svg        # Results browser mockup
    ├── MD3_Vulnerability_Details.svg   # Vulnerability details mockup
    ├── MD3_Scan_Runner.svg             # Scan wizard mockup
    ├── MD3_Reports.svg                 # Report generation mockup
    ├── MD3_Policies.svg                # Policy management mockup
    ├── MD3_Admin_Console.svg           # Admin interface mockup
    ├── MD3_Audit_Log.svg               # Audit trail mockup
    ├── MD3_Help_Docs.svg               # Help system mockup
    ├── MD3_Settings.svg                # Settings mockup
    ├── MD3_Playbooks.svg               # Playbooks mockup
    ├── MD3_Component_States.svg        # Component states reference
    ├── MD3_Dashboard_Light.svg         # Light theme variant
    ├── MD3_Scans_Mobile.svg            # Mobile responsive variant
    └── react-app/                      # Production React frontend
        ├── src/pages/                  # 33 page components
        ├── src/components/             # Shared UI components
        ├── src/hooks/                  # Custom React hooks
        ├── src/services/api.ts         # API client
        └── src/context/AuthContext.tsx  # Auth state management
```

## Design System

- **Framework:** React 18 + TypeScript + Vite + Material-UI (MUI)
- **Theme:** Dark mode with MD3 color palette
- **Typography:** Inter/Roboto system fonts

## SVG Mockups

15 SVG mockups (12 core + 3 variants) served as the original design reference. The production React app in `react-app/` implements and extends these designs with 33 pages.

## React Frontend

See `react-app/` for the production frontend. Start with:

```bash
cd design/ui/react-app
npm ci
npm run dev    # http://localhost:5088
```

Requires the API server running on port 8088. See the project README for setup instructions.
