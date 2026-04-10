from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Server
    host: str = "127.0.0.1"
    port: int = 8000

    # Workspace — all decompiled output, DB, certs stored here
    workspace_dir: Path = Path.home() / ".blujay"

    # Tool paths — defaults check tools/ dir relative to project root, then PATH
    java_path: str = "java"
    apktool_jar: Path = Path(__file__).parent.parent / "tools" / "apktool.jar"
    jadx_path: Path = Path(__file__).parent.parent / "tools" / "jadx" / "bin" / "jadx"
    adb_path: Path = Path(__file__).parent.parent / "tools" / "platform-tools" / "adb"
    libimobiledevice_dir: Path = Path("C:/tools/libimobiledevice")

    # Proxy
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8080

    # AODS (Android) — path to dyna.py (relative to repo root)
    aods_path: str = str(Path(__file__).parent.parent / "scanners" / "aods" / "dyna.py")
    # AODS venv python — use its own virtualenv so deps don't conflict
    aods_venv_python: str = str(Path(__file__).parent.parent / "scanners" / "aods" / "aods_venv" / "Scripts" / "python.exe")

    # IODS (iOS) — path to ios_scan.py (relative to repo root)
    iods_path: str = str(Path(__file__).parent.parent / "scanners" / "iods" / "ios_scan.py")
    # IODS venv python — use its own virtualenv so deps don't conflict
    iods_venv_python: str = str(Path(__file__).parent.parent / "scanners" / "iods" / "iods_venv" / "Scripts" / "python.exe")

    # MobileMorphAgent — project root for Gradle builds, and expected APK output path
    morph_agent_project: str = r"C:\Users\MalikSmith\repos\Malik_MobileMorph_Project\MobileMorphAgent\android_agent"
    morph_agent_apk: str = r"C:\Users\MalikSmith\repos\Malik_MobileMorph_Project\MobileMorphAgent\android_agent\app\build\outputs\apk\debug\mmagent-debug.apk"

    # Logging
    log_level: str = "INFO"

    @property
    def db_path(self) -> Path:
        return self.workspace_dir / "apkanalysis.db"

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"

    @property
    def decompile_dir(self) -> Path:
        return self.workspace_dir / "decompiled"

    @property
    def uploads_dir(self) -> Path:
        return self.workspace_dir / "uploads"

    @property
    def mitmproxy_cert_dir(self) -> Path:
        return self.workspace_dir / "mitmproxy-ca"

    @property
    def wordlists_dir(self) -> Path:
        return Path(__file__).parent / "wordlists"

    @property
    def screenshots_dir(self) -> Path:
        return self.workspace_dir / "screenshots"

    def ensure_dirs(self) -> None:
        for d in (self.workspace_dir, self.decompile_dir, self.uploads_dir,
                  self.mitmproxy_cert_dir, self.screenshots_dir):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
