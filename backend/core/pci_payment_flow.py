"""
PCI payment flow tester — uses Playwright to interactively navigate
payment flows, fill processor-appropriate test card data, capture
screenshots at each step, and intercept network traffic for CHD exposure.

Install: pip install playwright && playwright install chromium
"""
from __future__ import annotations
import asyncio
import base64
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from core.pci_models import PciFinding, PciEvidence, PciRemediation


# ── Test card data by processor ───────────────────────────────────────────────

TEST_CARDS: dict[str, dict[str, str]] = {
    "Stripe":        {"number": "4242424242424242", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
    "Braintree":     {"number": "4111111111111111", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
    "PayPal":        {"number": "4111111111111111", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
    "Square":        {"number": "4111111111111111", "exp": "12/26", "cvv": "111", "name": "Test Cardholder"},
    "Adyen":         {"number": "4111111111111111", "exp": "03/30", "cvv": "737", "name": "Test Cardholder"},
    "Authorize.Net": {"number": "4007000000027",   "exp": "12/26", "cvv": "900", "name": "Test Cardholder"},
    "Klarna":        {"number": "4111111111111111", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
    "Worldpay":      {"number": "4111111111111111", "exp": "12/26", "cvv": "737", "name": "Test Cardholder"},
    "Recurly":       {"number": "4111111111111111", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
    "Checkout.com":  {"number": "4242424242424242", "exp": "12/26", "cvv": "100", "name": "Test Cardholder"},
    "default":       {"number": "4111111111111111", "exp": "12/26", "cvv": "123", "name": "Test Cardholder"},
}


def _card_display(card: dict) -> str:
    digits = card["number"].replace(" ", "")
    return " ".join(digits[i:i+4] for i in range(0, len(digits), 4))


# ── Selectors ─────────────────────────────────────────────────────────────────

_CHECKOUT_SELS = [
    "button:has-text('Checkout')",
    "a:has-text('Checkout')",
    "button:has-text('Pay Now')",
    "button:has-text('Buy Now')",
    "button:has-text('Place Order')",
    "button:has-text('Continue to Payment')",
    "button:has-text('Proceed to Checkout')",
    "button:has-text('Add to Cart')",
    "a:has-text('Add to Cart')",
    "[data-testid*='checkout']",
    "button:has-text('Continue')",
    "a[href*='checkout']",
    "a[href*='/pay']",
]

_CARD_SELS = [
    "input[autocomplete='cc-number']",
    "input[name*='cardNumber']",
    "input[name*='card_number']",
    "input[name*='cc_number']",
    "input[name='pan']",
    "input[placeholder*='card number' i]",
    "input[placeholder*='1234' i]",
    "input[data-testid*='card-number']",
    "#card-number", "#cardNumber", "#cc-number", "#pan",
]

_CVV_SELS = [
    "input[autocomplete='cc-csc']",
    "input[name*='cvv']",
    "input[name*='cvc']",
    "input[name='securityCode']",
    "input[name='security_code']",
    "input[placeholder*='cvv' i]",
    "input[placeholder*='cvc' i]",
    "input[placeholder*='security code' i]",
    "#cvv", "#cvc", "#security-code", "#card-cvc",
]

_EXP_SELS = [
    "input[autocomplete='cc-exp']",
    "input[name*='expiry']",
    "input[name*='exp_date']",
    "input[name*='expDate']",
    "input[name='expiry']",
    "input[placeholder*='mm/yy' i]",
    "input[placeholder*='expir' i]",
    "#expiry", "#exp-date", "#card-expiry",
]

_PAN_RE = re.compile(r'4[0-9]{12}(?:[0-9]{3})?')


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class NetworkCapture:
    method: str
    url: str
    is_https: bool
    has_card_pattern: bool = False
    post_data_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "is_https": self.is_https,
            "has_card_pattern": self.has_card_pattern,
            "post_data_snippet": self.post_data_snippet,
        }


@dataclass
class FlowStep:
    step: int
    action: str
    url: str
    description: str
    screenshot_b64: Optional[str] = None
    elements_found: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "action": self.action,
            "url": self.url,
            "description": self.description,
            "screenshot_b64": self.screenshot_b64,
            "elements_found": self.elements_found,
            "notes": self.notes,
        }


@dataclass
class PaymentFlowResult:
    url: str
    processor: Optional[str] = None
    test_card: Optional[dict] = None
    reached_payment_form: bool = False
    steps: list[FlowStep] = field(default_factory=list)
    network_captures: list[NetworkCapture] = field(default_factory=list)
    findings: list[PciFinding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "processor": self.processor,
            "test_card": self.test_card,
            "reached_payment_form": self.reached_payment_form,
            "steps": [s.to_dict() for s in self.steps],
            "network_captures": [n.to_dict() for n in self.network_captures],
            "error": self.error,
        }


# ── Playwright helpers ────────────────────────────────────────────────────────

def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def _screenshot_b64(page) -> str | None:
    try:
        vp = page.viewport_size or {"width": 1024, "height": 640}
        data = await page.screenshot(
            type="jpeg", quality=62, full_page=False,
            clip={"x": 0, "y": 0, "width": vp["width"], "height": min(640, vp["height"])},
            timeout=6000,
        )
        return base64.b64encode(data).decode()
    except Exception:
        return None


def _detect_processor(html: str) -> str | None:
    from core.pci_scanner import _PROCESSOR_SIGS
    for name, patterns in _PROCESSOR_SIGS:
        if any(re.search(p, html, re.IGNORECASE) for p in patterns):
            return name
    return None


async def _first_visible(target, selectors: list[str], timeout_ms: int = 800) -> object | None:
    for sel in selectors:
        try:
            el = target.locator(sel).first
            if await el.is_visible(timeout=timeout_ms):
                return el
        except Exception:
            pass
    return None


async def _first_visible_in_frames(page, selectors: list[str], timeout_ms: int = 500) -> tuple | None:
    for frame in page.frames:
        for sel in selectors:
            try:
                el = frame.locator(sel).first
                if await el.is_visible(timeout=timeout_ms):
                    return frame, el
            except Exception:
                pass
    return None


async def _has_payment_form(page) -> bool:
    if await _first_visible(page, _CARD_SELS, timeout_ms=1000):
        return True
    return await _first_visible_in_frames(page, _CARD_SELS, timeout_ms=500) is not None


async def _detect_elements(page) -> list[str]:
    found = []
    for sels, label in [(_CARD_SELS, "card-number"), (_CVV_SELS, "cvv"), (_EXP_SELS, "expiry")]:
        if await _first_visible(page, sels, timeout_ms=600):
            found.append(label)
        elif await _first_visible_in_frames(page, sels, timeout_ms=400):
            found.append(f"{label}(iframe)")
    return found


async def _fill_field(target, selectors: list[str], value: str, label: str, filled: list[str]) -> None:
    for sel in selectors:
        try:
            el = target.locator(sel).first
            if await el.is_visible(timeout=600):
                await el.click(timeout=2000)
                await el.fill(value, timeout=2000)
                filled.append(label)
                return
        except Exception:
            pass


async def _fill_payment_form(page, card: dict) -> list[str]:
    filled: list[str] = []
    await _fill_field(page, _CARD_SELS, card["number"], "card-number", filled)
    await _fill_field(page, _EXP_SELS, card["exp"], "expiry", filled)
    await _fill_field(page, _CVV_SELS, card["cvv"], "cvv", filled)
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        if "card-number" not in filled:
            await _fill_field(frame, _CARD_SELS, card["number"], "card-number(iframe)", filled)
        if "expiry" not in filled:
            await _fill_field(frame, _EXP_SELS, card["exp"], "expiry(iframe)", filled)
        if "cvv" not in filled:
            await _fill_field(frame, _CVV_SELS, card["cvv"], "cvv(iframe)", filled)
    return filled


def _findings_from_form(url: str, html: str, elements: list[str]) -> list[PciFinding]:
    findings = []
    card_input_m = re.search(
        r'<input[^>]*(?:cc-number|card.?number|cardnumber|pan)[^>]*>', html, re.IGNORECASE
    )
    if card_input_m:
        inp = card_input_m.group(0)
        ac_m = re.search(r'autocomplete\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
        if not ac_m or ac_m.group(1).lower() not in ("off", "new-password"):
            findings.append(PciFinding(
                check_name="payment-autocomplete-confirmed",
                severity="medium",
                category="payment_flow",
                title="Card Field Autocomplete Confirmed Enabled (Browser Test)",
                detail=(
                    "Browser interaction confirmed the card number input does not disable autocomplete. "
                    "Browsers may cache CHD in their autofill store."
                ),
                target=url,
                remediation=PciRemediation(
                    'Set autocomplete="off" on all card input fields.',
                    pci_req="Req 3.4", priority=2,
                ),
                pci_req="Req 3.4",
                phase="payment_flow",
            ))

    direct_fields = [e for e in elements if "(iframe)" not in e]
    if not direct_fields and elements:
        findings.append(PciFinding(
            check_name="payment-fields-hosted-iframe",
            severity="info",
            category="payment_flow",
            title="Payment Fields Rendered in Cross-Origin Iframe",
            detail=(
                "Card fields are rendered inside a third-party hosted iframe "
                "(Stripe Elements, Braintree hosted fields, etc.). "
                "Verify the iframe loads exclusively from a PCI DSS Level 1 certified provider."
            ),
            target=url,
            remediation=PciRemediation(
                "Confirm iframe origin appears on Visa Global Registry of Service Providers.",
                pci_req="Req 12.8", priority=3,
            ),
            pci_req="Req 12.8",
            phase="payment_flow",
        ))
    elif not elements:
        findings.append(PciFinding(
            check_name="payment-form-no-interactable-fields",
            severity="medium",
            category="payment_flow",
            title="Payment Form Detected But No Interactable Card Fields Found",
            detail=(
                "A payment form context was detected but no interactive card input fields "
                "could be located. Fields may be dynamically injected, require prior steps "
                "(login, cart), or use a custom UI that doesn't match standard field identifiers."
            ),
            target=url,
            remediation=PciRemediation(
                "Ensure card fields use standard autocomplete attributes and accessible names.",
                pci_req="Req 6.4.3", priority=2,
            ),
            pci_req="Req 6.4.3",
            phase="payment_flow",
        ))
    return findings


# ── Core flow tester ──────────────────────────────────────────────────────────

async def test_payment_flow(url: str, processor_hint: str | None = None) -> PaymentFlowResult:
    """
    Launch a headless browser, navigate the payment flow at `url`,
    fill processor-appropriate test card data, and capture evidence.
    The form is NEVER submitted — testing stops after filling card fields.
    """
    result = PaymentFlowResult(url=url)

    if not _playwright_available():
        result.error = "playwright not installed — run: pip install playwright && playwright install chromium"
        result.findings.append(PciFinding(
            check_name="payment-flow-playwright-missing",
            severity="info",
            category="payment_flow",
            title="Payment Flow Testing Unavailable (Playwright Not Installed)",
            detail=(
                "Interactive browser-based payment flow testing requires Playwright. "
                "Run: pip install playwright && playwright install chromium"
            ),
            target=url,
            remediation=PciRemediation(
                "pip install playwright && playwright install chromium", priority=3,
            ),
            phase="payment_flow",
        ))
        return result

    from playwright.async_api import async_playwright

    network_events: list[dict] = []
    step_n = 0

    async with async_playwright() as pw:
        browser = None
        try:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                ],
            )
        except Exception as exc:
            result.error = (
                f"Browser launch failed: {exc}. "
                "Run: playwright install chromium"
            )
            result.findings.append(PciFinding(
                check_name="payment-flow-browser-launch-failed",
                severity="info",
                category="payment_flow",
                title="Payment Flow Testing Unavailable (Browser Launch Failed)",
                detail=str(exc)[:300],
                target=url,
                remediation=PciRemediation("Run: playwright install chromium", priority=3),
                phase="payment_flow",
            ))
            return result

        ctx = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1024, "height": 640},
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        def _on_request(req):
            try:
                network_events.append({
                    "method": req.method,
                    "url": req.url,
                    "is_https": req.url.startswith("https://"),
                    "post_data": (req.post_data or "")[:500],
                })
            except Exception:
                pass

        page.on("request", _on_request)

        try:
            # Step 1 — Navigate
            step_n += 1
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                await page.wait_for_timeout(1500)
            except Exception as exc:
                result.error = f"Navigation failed: {exc}"
                await browser.close()
                return result

            html = await page.content()
            proc = _detect_processor(html) or processor_hint
            result.processor = proc
            card = TEST_CARDS.get(proc or "", TEST_CARDS["default"])
            result.test_card = dict(card)

            ss = await _screenshot_b64(page)
            result.steps.append(FlowStep(
                step=step_n, action="navigate", url=page.url,
                description=f"Loaded {url}",
                screenshot_b64=ss,
                notes=f"Processor detected: {proc or 'none'}  |  Test card: {_card_display(card)}",
            ))

            # Step 2 — Navigate to payment form if not already there
            on_form = await _has_payment_form(page)

            if not on_form:
                for sel in _CHECKOUT_SELS:
                    try:
                        el = page.locator(sel).first
                        if await el.is_visible(timeout=700):
                            step_n += 1
                            await el.click(timeout=3000)
                            await page.wait_for_timeout(2000)
                            ss = await _screenshot_b64(page)
                            result.steps.append(FlowStep(
                                step=step_n, action="click-checkout",
                                url=page.url,
                                description=f"Clicked payment entry → {page.url}",
                                screenshot_b64=ss,
                            ))
                            on_form = await _has_payment_form(page)
                            break
                    except Exception:
                        pass

                # Second navigation attempt
                if not on_form:
                    for sel in _CHECKOUT_SELS:
                        try:
                            el = page.locator(sel).first
                            if await el.is_visible(timeout=600):
                                await el.click(timeout=3000)
                                await page.wait_for_timeout(2000)
                                on_form = await _has_payment_form(page)
                                if on_form:
                                    break
                        except Exception:
                            pass

            # Step 3 — Interact with payment form
            if on_form:
                result.reached_payment_form = True
                elements = await _detect_elements(page)
                step_n += 1
                ss = await _screenshot_b64(page)
                result.steps.append(FlowStep(
                    step=step_n, action="payment-form-detected",
                    url=page.url,
                    description="Payment form detected — card fields identified",
                    screenshot_b64=ss,
                    elements_found=elements,
                    notes=f"Fields: {', '.join(elements) or 'none interactable (likely hosted iframe)'}",
                ))

                # Fill test card — do NOT submit
                filled = await _fill_payment_form(page, card)
                await page.wait_for_timeout(800)

                step_n += 1
                masked = "•" * 12 + card["number"][-4:]
                ss_filled = await _screenshot_b64(page)
                result.steps.append(FlowStep(
                    step=step_n, action="test-card-filled",
                    url=page.url,
                    description=f"Test card filled — {masked}  [NOT submitted]",
                    screenshot_b64=ss_filled,
                    elements_found=filled,
                    notes=(
                        f"Card: {_card_display(card)}    Exp: {card['exp']}    CVV: {card['cvv']}\n"
                        f"Processor: {proc or 'unknown'}    "
                        f"Fields filled: {', '.join(filled) or 'none (cross-origin iframe)'}"
                    ),
                ))

                result.findings += _findings_from_form(page.url, html, elements)
                result.findings.insert(0, PciFinding(
                    check_name="payment-flow-reached",
                    severity="info",
                    category="payment_flow",
                    title=f"Payment Flow Reached — {proc or 'Unknown Processor'}",
                    detail=(
                        f"Browser successfully navigated to a payment form at {page.url}. "
                        f"Processor: {proc or 'unknown'}. "
                        f"Test card {masked} was filled but NOT submitted. "
                        f"Fields interacted: {', '.join(filled) or 'none — cross-origin hosted iframe'}."
                    ),
                    target=page.url,
                    evidence=PciEvidence(
                        notes=f"Steps: {step_n}  Processor: {proc}  Fields: {', '.join(filled) or 'iframe'}",
                    ),
                    phase="payment_flow",
                ))

            else:
                step_n += 1
                ss = await _screenshot_b64(page)
                result.steps.append(FlowStep(
                    step=step_n, action="flow-not-reached", url=page.url,
                    description="Could not navigate to a payment form from this URL",
                    screenshot_b64=ss,
                    notes=(
                        "Common causes: login required, no active cart/product, "
                        "URL doesn't lead directly to checkout, or bot protection is active."
                    ),
                ))
                result.findings.append(PciFinding(
                    check_name="payment-flow-not-reached",
                    severity="info",
                    category="payment_flow",
                    title="Payment Form Not Reachable from This URL",
                    detail=(
                        f"The browser could not navigate to a payment form starting from {url}. "
                        "Common causes: (1) login required, (2) active cart/product needed, "
                        "(3) URL doesn't lead to checkout, (4) bot detection is active."
                    ),
                    target=url,
                    remediation=PciRemediation(
                        "Provide the direct URL of the payment/checkout page in the scan scope.",
                        priority=3,
                    ),
                    phase="payment_flow",
                ))

        except Exception as exc:
            result.error = str(exc)[:400]
        finally:
            if browser:
                await browser.close()

    # Analyze captured network traffic
    for ev in network_events:
        pd = ev.get("post_data", "")
        has_card = bool(_PAN_RE.search(pd.replace(" ", "").replace("-", "")))
        result.network_captures.append(NetworkCapture(
            method=ev["method"],
            url=ev["url"][:200],
            is_https=ev["is_https"],
            has_card_pattern=has_card,
            post_data_snippet=pd[:200],
        ))
        if has_card and not ev["is_https"]:
            result.findings.append(PciFinding(
                check_name="card-data-http-request",
                severity="critical",
                category="payment_flow",
                title="Card Number Detected in Unencrypted HTTP Request",
                detail=(
                    f"A card number pattern was detected in a {ev['method']} request "
                    f"to {ev['url'][:150]} over plain HTTP during payment flow interaction."
                ),
                target=url,
                evidence=PciEvidence(notes=f"{ev['method']} {ev['url'][:200]}"),
                remediation=PciRemediation(
                    "All endpoints that receive card data must use HTTPS (TLS 1.2+).",
                    pci_req="Req 4.2.1", priority=1,
                ),
                pci_req="Req 4.2.1",
                phase="payment_flow",
            ))

    return result


# ── Batch runner ──────────────────────────────────────────────────────────────

async def run_payment_flow_tests(
    urls: list[str],
    processor_hints: dict[str, str] | None = None,
) -> list[PaymentFlowResult]:
    """Run interactive payment flow tests on each URL sequentially."""
    hints = processor_hints or {}
    results = []
    for url in urls:
        r = await test_payment_flow(url, hints.get(url))
        results.append(r)
    return results
