"""Lightweight string deobfuscation engine for Android malware analysis.

Decodes common obfuscation techniques found in Android malware:
- Base64 encoding
- Hex-encoded strings (quoted hex and \\xNN escape sequences)
- Single-byte XOR (byte arrays)
- Multi-byte XOR (2-4 byte repeating keys on quoted strings)
- ROT13 / ROT-N rotation
- String reversal
- Character array construction (new char[]{'h','e','l','l','o'})
- StringBuilder append chains (with or without initial value)
- Unicode escapes (\\uXXXX)
- String concatenation via variable assignments
- Bitwise char construction ((char)0x68, (char)104)
- String.valueOf(char) chains
- Array index lookup (STRS[0] + STRS[1] + ...)

Usage:
    from core.ml.deobfuscation import DeobfuscationEngine

    engine = DeobfuscationEngine()
    results = engine.deobfuscate_strings(java_source_content)
    # results: list of DeobfuscatedString with .original, .decoded, .method, .position
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import List, Optional, Set

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


@dataclass
class DeobfuscatedString:
    """A decoded string from obfuscated source code."""

    original: str
    decoded: str
    method: str  # base64, hex, hex_escape, xor_key_0xNN, multi_xor, rot13, etc.
    confidence: float = 0.0
    context: str = ""  # surrounding source code snippet
    position: int = -1  # byte offset in source (-1 = unknown)


# Minimum length for decoded strings to be considered interesting
_MIN_DECODED_LEN = 6
# Maximum length of an encoded blob to attempt decoding
_MAX_ENCODED_LEN = 4096
# Maximum number of candidates for brute-force decoders (XOR, multi-byte XOR)
_MAX_BRUTE_CANDIDATES = 30


def _is_printable_ascii(s: str) -> bool:
    """Check if a string is mostly printable ASCII (URLs, paths, commands)."""
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    return printable / len(s) > 0.85


# Pre-compiled interest patterns for performance
_INTEREST_REGEXES = [
    re.compile(pat, re.IGNORECASE)
    for pat in [
        r"https?://",
        r"ftps?://",
        r"file://",
        r"wss?://",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
        r"\.php\b",
        r"\.aspx?\b",
        r"/gate\.php|/panel/|/bot/|/upload|/c2/",  # C2 paths
        r"action=",
        r"cmd=",
        r"exec\(",
        r"su\b",
        r"/system/",
        r"/data/",
        r"android\.permission\.",
        r"getDeviceId",
        r"getSubscriberId",
        r"getLine1Number",
        r"SmsManager",
        r"TelephonyManager",
        r"ContentResolver",
        r"LocationManager",
        r"AccessibilityService",
        r"DeviceAdmin",
        r"Cipher",
        r"SecretKey",
        r"socket",
        r"connect\(",
        r"\.onion\b",
        r"bitcoin",
        r"wallet",
        r"ransom",
        r"encrypt",
        r"stratum\+",
        r"ACTION_INSTALL_PACKAGE|REQUEST_INSTALL_PACKAGES",
        r"\.tk\b|\.top\b|\.xyz\b|\.cc\b|\.ru\b",  # suspicious TLDs
        r"telegram\.org|api\.telegram",
        r"discord\.com/api/webhooks",
    ]
]


def _looks_interesting(decoded: str) -> bool:
    """Check if a decoded string looks like something a malware analyst cares about."""
    if len(decoded) < _MIN_DECODED_LEN:
        return False
    if not _is_printable_ascii(decoded):
        return False
    for pat in _INTEREST_REGEXES:
        if pat.search(decoded):
            return True
    return False


def _context_snippet(source: str, start: int, end: int) -> str:
    """Extract a context snippet around a match."""
    return source[max(0, start - 30):end + 30][:120]


class DeobfuscationEngine:
    """Decode common Android malware string obfuscation techniques."""

    # ------------------------------------------------------------------
    # Pre-compiled regexes (class-level for consistency & performance)
    # ------------------------------------------------------------------
    _BASE64_RE = re.compile(r'"([A-Za-z0-9+/]{12,}={0,2})"')
    _HEX_RE = re.compile(r'"([0-9a-fA-F]{12,})"')
    _HEX_ESCAPE_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
    _HEX_VAL_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
    _BYTE_ARRAY_RE = re.compile(r'new\s+byte\s*\[\s*\]\s*\{([^}]{10,500})\}')
    _BYTE_VAL_RE = re.compile(r'(0x[0-9a-fA-F]{1,2}|\d{1,3})')
    _HIGH_ENTROPY_STR_RE = re.compile(r'"([^"]{16,200})"')
    _ROT_CANDIDATE_RE = re.compile(r'"([a-zA-Z:/._\-]{10,200})"')
    _REVERSE_CANDIDATE_RE = re.compile(r'"([^"]{10,200})"')
    _REVERSE_DECODE_PATTERNS = re.compile(
        r"https?://|ftps?://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    )
    _CHAR_ARRAY_RE = re.compile(r'new\s+char\s*\[\s*\]\s*\{([^}]{6,1000})\}')
    _CHAR_LITERAL_RE = re.compile(r"'(.)'")
    _BUILDER_RE = re.compile(
        r'new\s+StringBuilder\s*\(\s*(?:"([^"]*)"\s*)?\)'
        r'((?:\s*\.append\s*\(\s*"[^"]*"\s*\))+)',
    )
    _APPEND_RE = re.compile(r'\.append\s*\(\s*"([^"]*)"\s*\)')
    _UNICODE_RE = re.compile(r'"((?:\\u[0-9a-fA-F]{4}){4,})"')
    _STR_ASSIGN_RE = re.compile(
        r'(?:String|final\s+String)\s+(\w+)\s*=\s*"([^"]{1,30})"\s*;'
    )
    _STR_CONCAT_RE = re.compile(
        r'((?:"[^"]*"|\w+)(?:\s*\+\s*(?:"[^"]*"|\w+)){2,})'
    )
    _CAST_CHAR_RE = re.compile(
        r'\(\s*char\s*\)\s*\(\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)'
    )
    _VALUEOF_CHAIN_RE = re.compile(
        r'((?:String\.valueOf\s*\(\s*\(\s*char\s*\)\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)\s*\+?\s*){3,})'
    )
    _VALUEOF_PART_RE = re.compile(
        r'String\.valueOf\s*\(\s*\(\s*char\s*\)\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)'
    )
    _STR_ARRAY_ASSIGN_RE = re.compile(
        r'(?:String\s*\[\s*\]\s+(\w+)\s*=\s*(?:new\s+String\s*\[\s*\]\s*)?'
        r'\{([^}]{6,2000})\})'
    )
    _ARRAY_CONCAT_RE = re.compile(
        r'((\w+)\s*\[\s*(\d+)\s*\](?:\s*\+\s*\w+\s*\[\s*\d+\s*\]){2,})'
    )

    def __init__(self, max_results: int = 100):
        self._max_results = max_results

    def deobfuscate_strings(self, source: str) -> List[DeobfuscatedString]:
        """Run all deobfuscation techniques on a source code string.

        Returns a list of successfully decoded strings sorted by confidence.
        Uses per-method budgeting to prevent early decoders from starving later ones.
        """
        methods = [
            self._decode_base64_strings,
            self._decode_hex_strings,
            self._decode_hex_escape_strings,
            self._decode_xor_strings,
            self._decode_multi_byte_xor,
            self._decode_rot_strings,
            self._decode_reversed_strings,
            self._decode_char_arrays,
            self._decode_string_builder,
            self._decode_unicode_escapes,
            self._decode_string_concat,
            self._decode_cast_chars,
            self._decode_valueof_chains,
            self._decode_array_index,
        ]

        # Per-method budget: each method gets a fair share, minimum 5
        per_method_cap = max(5, self._max_results // len(methods))

        results: List[DeobfuscatedString] = []
        seen: Set[str] = set()

        for method in methods:
            method_count = 0
            for result in method(source):
                if result.decoded not in seen:
                    seen.add(result.decoded)
                    results.append(result)
                    method_count += 1
                if method_count >= per_method_cap:
                    break
                if len(results) >= self._max_results:
                    break
            if len(results) >= self._max_results:
                break

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results[: self._max_results]

    # ------------------------------------------------------------------
    # Base64
    # ------------------------------------------------------------------

    def _decode_base64_strings(self, source: str) -> List[DeobfuscatedString]:
        """Find and decode base64-encoded strings."""
        results: List[DeobfuscatedString] = []
        for match in self._BASE64_RE.finditer(source):
            encoded = match.group(1)
            if len(encoded) > _MAX_ENCODED_LEN:
                continue
            try:
                decoded_bytes = base64.b64decode(encoded, validate=True)
                decoded = decoded_bytes.decode("utf-8", errors="replace")
                if _looks_interesting(decoded):
                    results.append(DeobfuscatedString(
                        original=encoded[:80],
                        decoded=decoded[:500],
                        method="base64",
                        confidence=0.85,
                        context=_context_snippet(source, match.start(), match.end()),
                        position=match.start(),
                    ))
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------
    # Hex (quoted continuous hex strings)
    # ------------------------------------------------------------------

    def _decode_hex_strings(self, source: str) -> List[DeobfuscatedString]:
        """Find and decode hex-encoded strings (0x68656C6C6F or "68656c6c6f")."""
        results: List[DeobfuscatedString] = []
        for match in self._HEX_RE.finditer(source):
            hex_str = match.group(1)
            if len(hex_str) % 2 != 0 or len(hex_str) > _MAX_ENCODED_LEN:
                continue
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
                if _looks_interesting(decoded):
                    results.append(DeobfuscatedString(
                        original=hex_str[:80],
                        decoded=decoded[:500],
                        method="hex",
                        confidence=0.80,
                        context=_context_snippet(source, match.start(), match.end()),
                        position=match.start(),
                    ))
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------
    # Hex escape sequences (\xNN\xNN...)
    # ------------------------------------------------------------------

    def _decode_hex_escape_strings(self, source: str) -> List[DeobfuscatedString]:
        r"""Decode \xNN hex escape sequences (e.g. \x68\x74\x74\x70)."""
        results: List[DeobfuscatedString] = []
        for match in self._HEX_ESCAPE_RE.finditer(source):
            raw = match.group(0)
            if len(raw) > _MAX_ENCODED_LEN:
                continue
            try:
                hex_vals = self._HEX_VAL_RE.findall(raw)
                decoded = bytes(int(h, 16) for h in hex_vals).decode("utf-8", errors="replace")
                if _looks_interesting(decoded):
                    results.append(DeobfuscatedString(
                        original=raw[:80],
                        decoded=decoded[:500],
                        method="hex_escape",
                        confidence=0.82,
                        context=_context_snippet(source, match.start(), match.end()),
                        position=match.start(),
                    ))
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------
    # Single-byte XOR (byte arrays)
    # ------------------------------------------------------------------

    def _decode_xor_strings(self, source: str) -> List[DeobfuscatedString]:
        """Find XOR-encrypted byte arrays and attempt single-byte XOR decode."""
        results: List[DeobfuscatedString] = []
        candidates = 0
        for match in self._BYTE_ARRAY_RE.finditer(source):
            candidates += 1
            if candidates > _MAX_BRUTE_CANDIDATES:
                break

            array_str = match.group(1)
            byte_vals: List[int] = []
            for val_match in self._BYTE_VAL_RE.finditer(array_str):
                val_str = val_match.group(1)
                try:
                    v = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                    if 0 <= v <= 255:
                        byte_vals.append(v)
                except ValueError:
                    continue

            if len(byte_vals) < _MIN_DECODED_LEN:
                continue

            best_decoded: Optional[str] = None
            best_key = 0
            best_score = 0.0

            for key in range(1, 256):
                decoded_bytes = bytes(b ^ key for b in byte_vals)
                try:
                    decoded = decoded_bytes.decode("ascii")
                    printable_ratio = sum(1 for c in decoded if 32 <= ord(c) < 127) / len(decoded)
                    if printable_ratio < 0.85:
                        continue
                    score = printable_ratio
                    if _looks_interesting(decoded):
                        score += 1.0
                    if score > best_score:
                        best_score = score
                        best_decoded = decoded
                        best_key = key
                except UnicodeDecodeError:
                    continue

            if best_decoded and _looks_interesting(best_decoded):
                results.append(DeobfuscatedString(
                    original=array_str[:80],
                    decoded=best_decoded[:500],
                    method=f"xor_key_0x{best_key:02x}",
                    confidence=0.70,
                    context=_context_snippet(source, match.start(), match.end()),
                    position=match.start(),
                ))
        return results

    # ------------------------------------------------------------------
    # Multi-byte XOR (2-4 byte repeating keys on quoted strings)
    # ------------------------------------------------------------------

    def _decode_multi_byte_xor(self, source: str) -> List[DeobfuscatedString]:
        """Try 2-4 byte repeating XOR keys on high-entropy quoted strings.

        Targets strings that look like binary data encoded as Latin-1 in source.
        Limited to 30 candidates x key_lengths {2,3,4} to bound CPU cost.
        """
        results: List[DeobfuscatedString] = []
        candidates = []
        for m in self._HIGH_ENTROPY_STR_RE.finditer(source):
            val = m.group(1)
            # Skip strings that are already printable English / code
            non_alnum = sum(1 for c in val if not c.isalnum() and c not in " _.-/:")
            if non_alnum / max(len(val), 1) < 0.15:
                continue
            candidates.append(m)
            if len(candidates) >= _MAX_BRUTE_CANDIDATES:
                break

        seen: Set[str] = set()

        for m in candidates:
            raw_bytes = m.group(1).encode("latin-1", errors="ignore")
            if len(raw_bytes) < 8:
                continue

            for key_len in (2, 3, 4):
                # Use known-plaintext attack: assume first bytes are "http" or common prefix
                for known_prefix in (b"http", b"https", b"/data", b"exec"):
                    if len(known_prefix) < key_len:
                        continue
                    key = bytes(raw_bytes[i] ^ known_prefix[i] for i in range(key_len))
                    if all(b == 0 for b in key):
                        continue
                    decoded_bytes = bytes(raw_bytes[i] ^ key[i % key_len] for i in range(len(raw_bytes)))
                    try:
                        decoded = decoded_bytes.decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        continue
                    if not _is_printable_ascii(decoded):
                        continue
                    if decoded in seen:
                        continue
                    if _looks_interesting(decoded):
                        seen.add(decoded)
                        key_hex = key.hex()
                        results.append(DeobfuscatedString(
                            original=m.group(1)[:80],
                            decoded=decoded[:500],
                            method=f"multi_xor_{key_len}b_0x{key_hex}",
                            confidence=0.65,
                            context=_context_snippet(source, m.start(), m.end()),
                            position=m.start(),
                        ))
                        break  # Found a good key for this candidate
                else:
                    continue
                break  # Already found a match, move to next candidate

        return results

    # ------------------------------------------------------------------
    # ROT13 / ROT-N rotation
    # ------------------------------------------------------------------

    def _decode_rot_strings(self, source: str) -> List[DeobfuscatedString]:
        """Try ROT13 and ROT-N (1-25) on quoted alpha strings."""
        results: List[DeobfuscatedString] = []

        for match in self._ROT_CANDIDATE_RE.finditer(source):
            s = match.group(1)
            # Only try rotation if the string doesn't already look interesting
            if _looks_interesting(s):
                continue

            for n in (13, 5, 7, 11, 19, 23):  # Common rotations, ROT13 first
                rotated = self._rotate_alpha(s, n)
                if _looks_interesting(rotated):
                    method = "rot13" if n == 13 else f"rot{n}"
                    results.append(DeobfuscatedString(
                        original=s[:80],
                        decoded=rotated[:500],
                        method=method,
                        confidence=0.55 if n != 13 else 0.65,
                        context=_context_snippet(source, match.start(), match.end()),
                        position=match.start(),
                    ))
                    break  # First match wins

        return results

    @staticmethod
    def _rotate_alpha(s: str, n: int) -> str:
        """Rotate only alphabetic characters by n positions."""
        out = []
        for c in s:
            if "a" <= c <= "z":
                out.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                out.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
            else:
                out.append(c)
        return "".join(out)

    # ------------------------------------------------------------------
    # String reversal
    # ------------------------------------------------------------------

    def _decode_reversed_strings(self, source: str) -> List[DeobfuscatedString]:
        """Find strings that are reversed versions of interesting content."""
        results: List[DeobfuscatedString] = []
        for match in self._REVERSE_CANDIDATE_RE.finditer(source):
            s = match.group(1)
            reversed_s = s[::-1]
            if (
                self._REVERSE_DECODE_PATTERNS.search(reversed_s)
                and not self._REVERSE_DECODE_PATTERNS.search(s)
                and _is_printable_ascii(reversed_s)
            ):
                results.append(DeobfuscatedString(
                    original=s[:80],
                    decoded=reversed_s[:500],
                    method="reverse",
                    confidence=0.60,
                    context=_context_snippet(source, match.start(), match.end()),
                    position=match.start(),
                ))
        return results

    # ------------------------------------------------------------------
    # Character array construction
    # ------------------------------------------------------------------

    def _decode_char_arrays(self, source: str) -> List[DeobfuscatedString]:
        """Decode new char[]{'h','e','l','l','o'} style obfuscation."""
        results: List[DeobfuscatedString] = []
        for match in self._CHAR_ARRAY_RE.finditer(source):
            char_str = match.group(1)
            chars = self._CHAR_LITERAL_RE.findall(char_str)
            if len(chars) < _MIN_DECODED_LEN:
                continue
            decoded = "".join(chars)
            if _looks_interesting(decoded):
                results.append(DeobfuscatedString(
                    original=char_str[:80],
                    decoded=decoded[:500],
                    method="char_array",
                    confidence=0.90,
                    context=_context_snippet(source, match.start(), match.end()),
                    position=match.start(),
                ))
        return results

    # ------------------------------------------------------------------
    # StringBuilder append chains (with or without initial value)
    # ------------------------------------------------------------------

    def _decode_string_builder(self, source: str) -> List[DeobfuscatedString]:
        """Decode StringBuilder chains, including StringBuilder("initial").append(...)."""
        results: List[DeobfuscatedString] = []
        for match in self._BUILDER_RE.finditer(source):
            initial = match.group(1) or ""  # group(1) is the optional initial string
            chain = match.group(2)
            parts = self._APPEND_RE.findall(chain)
            # Require at least 2 appends (or 1 append + initial value)
            min_appends = 2 if not initial else 1
            if len(parts) < min_appends:
                continue
            decoded = initial + "".join(parts)
            if len(decoded) >= _MIN_DECODED_LEN and _looks_interesting(decoded):
                results.append(DeobfuscatedString(
                    original=chain[:80],
                    decoded=decoded[:500],
                    method="string_builder",
                    confidence=0.85,
                    context=_context_snippet(source, match.start(), match.end()),
                    position=match.start(),
                ))
        return results

    # ------------------------------------------------------------------
    # Unicode escapes
    # ------------------------------------------------------------------

    def _decode_unicode_escapes(self, source: str) -> List[DeobfuscatedString]:
        """Decode \\uXXXX unicode escape sequences in string literals."""
        results: List[DeobfuscatedString] = []
        for match in self._UNICODE_RE.finditer(source):
            escaped = match.group(1)
            try:
                decoded = escaped.encode("raw_unicode_escape").decode("unicode_escape")
                if _looks_interesting(decoded):
                    results.append(DeobfuscatedString(
                        original=escaped[:80],
                        decoded=decoded[:500],
                        method="unicode",
                        confidence=0.90,
                        context=_context_snippet(source, match.start(), match.end()),
                        position=match.start(),
                    ))
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------
    # String concatenation via variable assignments
    # ------------------------------------------------------------------

    def _decode_string_concat(self, source: str) -> List[DeobfuscatedString]:
        """Resolve string concatenation via variable assignment patterns.

        Handles both variable-first (a + b + c) and literal-first ("ht" + "tp" + x).
        """
        results: List[DeobfuscatedString] = []

        # Build variable map from String assignments
        var_map: dict[str, str] = {}
        for m in self._STR_ASSIGN_RE.finditer(source):
            var_map[m.group(1)] = m.group(2)

        # Find concatenation expressions (now matches literal-first too)
        for m in self._STR_CONCAT_RE.finditer(source):
            expr = m.group(1)
            parts = re.split(r'\s*\+\s*', expr)
            if len(parts) < 3:
                continue

            resolved_parts: List[str] = []
            resolvable = True
            for part in parts:
                part = part.strip()
                # Quoted string literal
                str_match = re.match(r'^"([^"]*)"$', part)
                if str_match:
                    resolved_parts.append(str_match.group(1))
                # Variable reference
                elif part in var_map:
                    resolved_parts.append(var_map[part])
                else:
                    resolvable = False
                    break

            if not resolvable or len(resolved_parts) < 3:
                continue

            decoded = "".join(resolved_parts)
            if len(decoded) >= _MIN_DECODED_LEN and _looks_interesting(decoded):
                results.append(DeobfuscatedString(
                    original=expr[:80],
                    decoded=decoded[:500],
                    method="string_concat",
                    confidence=0.75,
                    context=_context_snippet(source, m.start(), m.end()),
                    position=m.start(),
                ))

        return results

    # ------------------------------------------------------------------
    # Bitwise char construction: (char)(0x68), (char)(104)
    # ------------------------------------------------------------------

    def _decode_cast_chars(self, source: str) -> List[DeobfuscatedString]:
        """Decode sequences of (char)(0xNN) or (char)(NNN) casts concatenated together."""
        results: List[DeobfuscatedString] = []
        # Find runs of (char)(value) separated by + or concatenation
        # Strategy: collect all cast positions, find consecutive runs
        casts = list(self._CAST_CHAR_RE.finditer(source))
        if len(casts) < _MIN_DECODED_LEN:
            return results

        # Group consecutive casts (within 60 chars of each other)
        groups: List[List[re.Match]] = []
        current_group: List[re.Match] = [casts[0]]
        for i in range(1, len(casts)):
            if casts[i].start() - casts[i - 1].end() < 60:
                current_group.append(casts[i])
            else:
                if len(current_group) >= _MIN_DECODED_LEN:
                    groups.append(current_group)
                current_group = [casts[i]]
        if len(current_group) >= _MIN_DECODED_LEN:
            groups.append(current_group)

        for group in groups:
            chars = []
            for m in group:
                val_str = m.group(1)
                try:
                    v = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                    if 32 <= v < 127:
                        chars.append(chr(v))
                    else:
                        break  # Non-printable = probably not text
                except ValueError:
                    break
            if len(chars) < _MIN_DECODED_LEN:
                continue
            decoded = "".join(chars)
            if _looks_interesting(decoded):
                original = source[group[0].start():group[-1].end()]
                results.append(DeobfuscatedString(
                    original=original[:80],
                    decoded=decoded[:500],
                    method="cast_char",
                    confidence=0.88,
                    context=_context_snippet(source, group[0].start(), group[-1].end()),
                    position=group[0].start(),
                ))

        return results

    # ------------------------------------------------------------------
    # String.valueOf(char) chains
    # ------------------------------------------------------------------

    def _decode_valueof_chains(self, source: str) -> List[DeobfuscatedString]:
        """Decode String.valueOf((char)NNN) + String.valueOf((char)NNN) chains."""
        results: List[DeobfuscatedString] = []
        for match in self._VALUEOF_CHAIN_RE.finditer(source):
            chain = match.group(1)
            parts = self._VALUEOF_PART_RE.findall(chain)
            if len(parts) < _MIN_DECODED_LEN:
                continue
            chars = []
            for val_str in parts:
                try:
                    v = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                    if 32 <= v < 127:
                        chars.append(chr(v))
                    else:
                        break
                except ValueError:
                    break
            if len(chars) < _MIN_DECODED_LEN:
                continue
            decoded = "".join(chars)
            if _looks_interesting(decoded):
                results.append(DeobfuscatedString(
                    original=chain[:80],
                    decoded=decoded[:500],
                    method="valueof_chain",
                    confidence=0.88,
                    context=_context_snippet(source, match.start(), match.end()),
                    position=match.start(),
                ))
        return results

    # ------------------------------------------------------------------
    # Array index lookup: STRS[0] + STRS[1] + ...
    # ------------------------------------------------------------------

    def _decode_array_index(self, source: str) -> List[DeobfuscatedString]:
        """Decode String[] array lookups concatenated together."""
        results: List[DeobfuscatedString] = []

        # Build array maps: name -> {index: value}
        array_map: dict[str, dict[int, str]] = {}
        for m in self._STR_ARRAY_ASSIGN_RE.finditer(source):
            name = m.group(1)
            vals_str = m.group(2)
            vals = re.findall(r'"([^"]*)"', vals_str)
            array_map[name] = {i: v for i, v in enumerate(vals)}

        if not array_map:
            return results

        # Find array[idx] + array[idx] + ... concatenation
        for m in self._ARRAY_CONCAT_RE.finditer(source):
            expr = m.group(1)
            arr_name = m.group(2)
            if arr_name not in array_map:
                continue
            arr = array_map[arr_name]
            # Extract all indices from this expression
            index_parts = re.findall(rf'{re.escape(arr_name)}\s*\[\s*(\d+)\s*\]', expr)
            if len(index_parts) < 3:
                continue
            resolved: List[str] = []
            resolvable = True
            for idx_str in index_parts:
                idx = int(idx_str)
                if idx in arr:
                    resolved.append(arr[idx])
                else:
                    resolvable = False
                    break
            if not resolvable or len(resolved) < 3:
                continue
            decoded = "".join(resolved)
            if len(decoded) >= _MIN_DECODED_LEN and _looks_interesting(decoded):
                results.append(DeobfuscatedString(
                    original=expr[:80],
                    decoded=decoded[:500],
                    method="array_index",
                    confidence=0.80,
                    context=_context_snippet(source, m.start(), m.end()),
                    position=m.start(),
                ))

        return results


# Convenience function for quick deobfuscation
def deobfuscate(source: str, max_results: int = 100) -> List[DeobfuscatedString]:
    """Deobfuscate strings in source code. Convenience wrapper."""
    engine = DeobfuscationEngine(max_results=max_results)
    return engine.deobfuscate_strings(source)
