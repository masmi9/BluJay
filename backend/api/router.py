from fastapi import APIRouter

from api.analysis import router as analysis_router
from api.adb import router as adb_router
from api.session import router as session_router
from api.proxy import router as proxy_router
from api.frida import router as frida_router
from api.settings import router as settings_router
from api.agent import router as agent_router
from api.owasp import router as owasp_router
from api.testing import router as testing_router
from api.screenshot import router as screenshot_router
from api.cve import router as cve_router
from api.webview import router as webview_router
from api.tls_audit import router as tls_router
from api.jwt_test import router as jwt_router
from api.risk import router as risk_router
from api.fuzzing import router as fuzzing_router
from api.brute_force import router as brute_force_router
from api.ipa import router as ipa_router
from api.ios_devices import router as ios_devices_router
from api.ollama import router as ollama_router
from api.strix import router as strix_router
from api.api_testing import router as api_testing_router
from api.objection import router as objection_router
from api.diff import router as diff_router
from api.campaign import router as campaign_router
from api.scanner import router as scanner_router

api_router = APIRouter()
api_router.include_router(analysis_router, prefix="/analyses", tags=["analysis"])
api_router.include_router(adb_router, prefix="/devices", tags=["adb"])
api_router.include_router(session_router, prefix="/sessions", tags=["sessions"])
api_router.include_router(proxy_router, prefix="/proxy", tags=["proxy"])
api_router.include_router(frida_router, prefix="/frida", tags=["frida"])
api_router.include_router(settings_router, prefix="/settings", tags=["settings"])
api_router.include_router(agent_router, prefix="/agent", tags=["agent"])
api_router.include_router(owasp_router, prefix="/owasp", tags=["owasp"])
api_router.include_router(testing_router, prefix="/testing", tags=["testing"])
api_router.include_router(screenshot_router, prefix="/screenshots", tags=["screenshots"])
api_router.include_router(cve_router, prefix="/cve", tags=["cve"])
api_router.include_router(webview_router, prefix="/webview", tags=["webview"])
api_router.include_router(tls_router, prefix="/tls", tags=["tls"])
api_router.include_router(jwt_router, prefix="/jwt", tags=["jwt"])
api_router.include_router(risk_router, prefix="/risk", tags=["risk"])
api_router.include_router(fuzzing_router, prefix="/fuzzing", tags=["fuzzing"])
api_router.include_router(brute_force_router, prefix="/brute-force", tags=["brute-force"])
api_router.include_router(ipa_router, prefix="/ipa", tags=["ipa"])
api_router.include_router(ios_devices_router, prefix="/ios-devices", tags=["ios"])
api_router.include_router(ollama_router, prefix="/ollama", tags=["ollama"])
api_router.include_router(strix_router, prefix="/strix", tags=["strix"])
api_router.include_router(api_testing_router, prefix="/api-testing", tags=["api-testing"])
api_router.include_router(objection_router, prefix="/objection", tags=["objection"])
api_router.include_router(diff_router, prefix="/diff", tags=["diff"])
api_router.include_router(campaign_router, prefix="/campaigns", tags=["campaigns"])
api_router.include_router(scanner_router, prefix="/scanner", tags=["scanner"])

# Singletons initialised lazily (so imports don't fail before lifespan runs)
_proxy_manager = None
_frida_manager = None


def get_proxy_manager():
    global _proxy_manager
    if _proxy_manager is None:
        from core.proxy_manager import ProxyManager
        from database import AsyncSessionLocal
        _proxy_manager = ProxyManager(AsyncSessionLocal)
    return _proxy_manager


def get_frida_manager():
    global _frida_manager
    if _frida_manager is None:
        from core.frida_manager import FridaManager
        from database import AsyncSessionLocal
        _frida_manager = FridaManager(AsyncSessionLocal)
    return _frida_manager
