#!/usr/bin/env python3
"""
compile_jsp.py — Compile .jsp to bytecode via Docker Tomcat and return javap output.

Architecture (no polling, no docker cp):
  1. Write the JSP into the container's webapps/ROOT directory.
  2. Send an HTTP GET — Tomcat/Jasper compiles synchronously; response comes back
     when compilation is done (200 OK) or after a runtime error (HTTP 500, which
     still means the .class was written).
  3. Find the compiled .class path with one `docker exec find`.
  4. Run `docker exec javap` inside the container to get the bytecode text.
  5. Delete the .class and the JSP.  Nothing leaves the container.

Two-pass strategy for JSPs with framework tag libraries (Spring, JSTL, etc.):
  Pass 1 — compile the JSP as-is.
  Pass 2 — strip taglib directives and custom tags; keep only <%@ page %> and
            scriptlet blocks (<% %>, <%! %>, <%= %>).  Webshell payloads live
            in scriptlets, so the dangerous bytecode is preserved.

Public API
----------
  compile_jsp(jsp_path) -> str
      Returns the javap -c -p -verbose output for the compiled class, or raises
      RuntimeError if both passes fail or the JSP has no Java content.
"""

import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT        = Path(__file__).parent.parent
WEBAPPS_DIR = ROOT / "jsp_workspace" / "webapps"
TOMCAT_URL  = os.environ.get("TOMCAT_URL", "http://localhost:9090")
CONTAINER   = "shellbreaker-tomcat"
WORK_PATH   = "/usr/local/tomcat/work"
AGENT_LOG   = ROOT / "agent" / "sb_agent.log"

# ---------------------------------------------------------------------------
# Docker socket resolution
# ---------------------------------------------------------------------------

def _resolve_docker_host() -> dict:
    current = os.environ.get("DOCKER_HOST", "")
    if current:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=3)
        if r.returncode == 0:
            return {}
    for sock in ("/var/run/docker.sock", "/run/docker.sock"):
        if Path(sock).exists():
            env = os.environ.copy()
            env["DOCKER_HOST"] = f"unix://{sock}"
            r = subprocess.run(["docker", "info"], capture_output=True, env=env, timeout=3)
            if r.returncode == 0:
                return {"DOCKER_HOST": f"unix://{sock}"}
    return {}


_DOCKER_ENV:   dict = {}
_TOMCAT_READY: bool = False


def _docker(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(_DOCKER_ENV)
    return subprocess.run(["docker"] + args, env=env, **kwargs)


# ---------------------------------------------------------------------------
# Tomcat lifecycle (idempotent — only runs once per process)
# ---------------------------------------------------------------------------

def try_ensure_tomcat() -> bool:
    """Non-fatal version of ensure_tomcat(). Returns True if Tomcat is ready,
    False if Docker is unavailable or the container cannot be started."""
    global _DOCKER_ENV, _TOMCAT_READY
    if _TOMCAT_READY:
        return True
    _DOCKER_ENV = _resolve_docker_host()
    try:
        _docker(["info"], capture_output=True, check=True, timeout=5)
    except Exception:
        return False

    r = _docker(["inspect", "-f", "{{.State.Running}}", CONTAINER],
                capture_output=True, text=True, timeout=5)
    if r.stdout.strip() != "true":
        print("  Starting Tomcat container (first pull may take ~30 s) ...")
        WEBAPPS_DIR.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy(); env.update(_DOCKER_ENV)
        r = subprocess.run(
            ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
             "up", "-d", "tomcat"],
            capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            return False

    WEBAPPS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        WEBAPPS_DIR.chmod(0o777)
    except PermissionError:
        pass

    print("  Waiting for Tomcat ...", end="", flush=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{TOMCAT_URL}/", timeout=2)
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    else:
        print(f"\n  [WARN] Tomcat not ready — falling back to local compilation.",
              file=sys.stderr)
        return False

    print(" ready.")
    _TOMCAT_READY = True
    return True


def ensure_tomcat() -> None:
    global _DOCKER_ENV, _TOMCAT_READY
    if _TOMCAT_READY:
        return

    _DOCKER_ENV = _resolve_docker_host()

    try:
        _docker(["info"], capture_output=True, check=True, timeout=5)
    except Exception:
        print(
            "  [ERROR] Docker is not running.\n"
            "  Install Docker and start it, then run:  docker compose up -d",
            file=sys.stderr,
        )
        sys.exit(1)

    # Start container if needed
    r = _docker(["inspect", "-f", "{{.State.Running}}", CONTAINER],
                capture_output=True, text=True, timeout=5)
    if r.stdout.strip() != "true":
        print("  Starting Tomcat container (first pull may take ~30 s) ...")
        WEBAPPS_DIR.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy(); env.update(_DOCKER_ENV)
        r = subprocess.run(
            ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
             "up", "-d", "tomcat"],
            capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            print(f"  [ERROR] docker compose failed:\n{r.stderr}", file=sys.stderr)
            sys.exit(1)

    # Ensure webapps dir is writable (Docker creates it as root)
    WEBAPPS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        WEBAPPS_DIR.chmod(0o777)
    except PermissionError:
        pass

    # Wait for HTTP readiness
    print("  Waiting for Tomcat ...", end="", flush=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{TOMCAT_URL}/", timeout=2)
            break
        except urllib.error.HTTPError:
            break   # 404 = up but no default app — that's fine
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    else:
        print(f"\n  [ERROR] Tomcat did not become ready within 60 s.", file=sys.stderr)
        sys.exit(1)

    print(" ready.")
    _TOMCAT_READY = True


# ---------------------------------------------------------------------------
# JSP preprocessing — strip framework dependencies for pass 2
# ---------------------------------------------------------------------------

_PAGE_DIR_RE = re.compile(r'<%@\s*page\b.*?%>',    re.DOTALL | re.IGNORECASE)
_SCRIPTLET_RE = re.compile(r'<%(?!@)(=|!)?.*?%>', re.DOTALL)
_TAGLIB_RE    = re.compile(r'<%@\s*taglib\b.*?%>', re.DOTALL | re.IGNORECASE)

# Removed-API import lines — stripped so Jasper doesn't reject them
_REMOVED_IMPORTS = re.compile(
    r'<%@\s*page\s+import\s*=\s*"(sun\.misc\.BASE64(?:De|En)coder'
    r'|sun\.misc\.BASE64'
    r'|com\.sun\.[^"]*)"[^%]*%>\s*\n?',
    re.IGNORECASE,
)

def _compat_rewrite(source: str) -> str:
    """Replace removed JDK APIs so the JSP compiles on JDK 11+.
    Substitutions preserve the dangerous logic — only the API surface changes."""
    # Drop import directives for removed sun.misc.BASE64* classes
    source = _REMOVED_IMPORTS.sub("", source)
    # Replace BASE64Decoder usage with java.util.Base64 equivalent
    source = re.sub(
        r'new\s+BASE64Decoder\(\)\.decodeBuffer\(',
        'java.util.Base64.getDecoder().decode(',
        source,
    )
    source = re.sub(
        r'new\s+sun\.misc\.BASE64Decoder\(\)\.decodeBuffer\(',
        'java.util.Base64.getDecoder().decode(',
        source,
    )
    source = re.sub(
        r'new\s+BASE64Encoder\(\)\.encode\(',
        'java.util.Base64.getEncoder().encodeToString(',
        source,
    )
    source = re.sub(
        r'new\s+sun\.misc\.BASE64Encoder\(\)\.encode\(',
        'java.util.Base64.getEncoder().encodeToString(',
        source,
    )
    return source

def _strip_to_scriptlets(source: str) -> str | None:
    """Keep <%@ page %> + all scriptlet blocks; drop taglibs, HTML, custom tags.
    Always returns a compilable stub so ML can score even pure-template JSPs.
    Returns None only if the source has no JSP content at all (static HTML/XML)."""
    page_dirs  = [m.group(0) for m in _PAGE_DIR_RE.finditer(source)]
    scriptlets = [m.group(0) for m in _SCRIPTLET_RE.finditer(source)]
    has_taglibs = bool(_TAGLIB_RE.search(source))
    if not page_dirs and not scriptlets and not has_taglibs:
        return None
    # Ensure Jasper always has at least one page directive to compile against
    if not page_dirs:
        page_dirs = ['<%@ page contentType="text/html;charset=UTF-8" language="java" %>']
    # Tomcat 10 uses jakarta.servlet.*; older JSPs import javax.servlet.* — rewrite
    page_dirs = [d.replace("javax.servlet", "jakarta.servlet")
                  .replace("javax.websocket", "jakarta.websocket") for d in page_dirs]
    return "\n".join(page_dirs + scriptlets)


# ---------------------------------------------------------------------------
# WEB-INF discovery and injection (Option A)
# ---------------------------------------------------------------------------

_WEBINF_MOUNTED: bool = False   # only copy once per process


def _find_webinf(jsp_path: Path) -> Path | None:
    """Walk up from the JSP file to find the nearest WEB-INF/ directory."""
    for parent in [jsp_path.parent, *jsp_path.parent.parents]:
        candidate = parent / "WEB-INF"
        if candidate.is_dir():
            return candidate
    return None


def _mount_webinf(webinf_path: Path) -> None:
    """Copy WEB-INF/classes and WEB-INF/lib into the container's webapps ROOT."""
    global _WEBINF_MOUNTED
    if _WEBINF_MOUNTED:
        return

    container_webinf = "/usr/local/tomcat/webapps/ROOT/WEB-INF"
    _docker(["exec", CONTAINER, "mkdir", "-p",
             f"{container_webinf}/classes", f"{container_webinf}/lib"],
            capture_output=True)

    for subdir in ("classes", "lib"):
        src = webinf_path / subdir
        if src.exists():
            _docker(
                ["cp", str(src) + "/.", f"{CONTAINER}:{container_webinf}/{subdir}/"],
                capture_output=True, timeout=30,
            )

    _WEBINF_MOUNTED = True
    print(f"  [JSP] Mounted WEB-INF from {webinf_path} into container.")


# ---------------------------------------------------------------------------
# Agent log helpers (dynamic analysis)
# ---------------------------------------------------------------------------

def _clear_agent_log() -> None:
    try:
        if AGENT_LOG.exists():
            AGENT_LOG.write_text("")
    except Exception:
        pass


def _read_agent_log(since_ms: int = 0) -> list[str]:
    """Return deduplicated API labels logged at or after since_ms.
    Strips the 'api:' prefix so labels match _DANGER_DYNAMIC in scan_bulk.py.
    since_ms prevents hits from a previous JSP bleeding into the current one."""
    try:
        if not AGENT_LOG.exists():
            return []
        labels: set[str] = set()
        for line in AGENT_LOG.read_text(errors="replace").splitlines():
            parts = line.split("|")
            if len(parts) < 2 or not parts[1]:
                continue
            # Filter by timestamp to avoid bleed from previous JSP executions
            if since_ms:
                try:
                    if int(parts[0]) < since_ms:
                        continue
                except ValueError:
                    pass
            label = parts[1]
            if label.startswith("api:"):
                label = label[4:]
            labels.add(label)
        return sorted(labels)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Core: compile one JSP name+content, return (javap_text, dynamic_hits)
# ---------------------------------------------------------------------------

def _compile_one(deploy_name: str, source: str) -> tuple[str, list[str]]:
    """
    Deploy source as deploy_name, trigger Tomcat to compile it via HTTP,
    then run javap inside the container and return the output.
    Also returns dynamic API hits captured by the Java agent during execution.
    Returns ("", []) if compilation produced no class file.
    """
    _clear_agent_log()
    request_start_ms = int(time.time() * 1000)

    deploy_path = WEBAPPS_DIR / deploy_name
    deploy_path.write_text(source, encoding="utf-8", errors="replace")

    # HTTP GET triggers synchronous JSP compilation.
    # 200 = compiled + ran OK.  500 = compiled but threw runtime error (still
    # have a .class).  404 = file not found (shouldn't happen).  Connection
    # errors mean the container is overloaded — treat as failure.
    try:
        urllib.request.urlopen(f"{TOMCAT_URL}/{deploy_name}", timeout=15)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            deploy_path.unlink(missing_ok=True)
            return "", []
        # 500 with "Unable to compile" = Jasper syntax error, no .class written
        try:
            body = e.read().decode(errors="replace")
            if "Unable to compile" in body or "Syntax error" in body:
                deploy_path.unlink(missing_ok=True)
                return "", []
        except Exception:
            pass
        # Any other 500 = compiled but threw at runtime — .class exists
    except Exception:
        deploy_path.unlink(missing_ok=True)
        return "", []
    finally:
        deploy_path.unlink(missing_ok=True)

    # Read dynamic hits — only entries logged after this request started
    dynamic_hits = _read_agent_log(since_ms=request_start_ms)

    # Find the compiled .class inside the container (one call, no polling).
    r = _docker(
        ["exec", CONTAINER, "find", WORK_PATH, "-name", "*_jsp*.class"],
        capture_output=True, text=True, timeout=10,
    )
    class_paths = [p for p in r.stdout.strip().splitlines() if p]
    if not class_paths:
        return "", dynamic_hits

    # Run javap inside the container — no docker cp needed.
    javap_parts: list[str] = []
    for cp in class_paths:
        jr = _docker(
            ["exec", CONTAINER,
             "javap", "-c", "-p", "-verbose", cp],
            capture_output=True, text=True, timeout=15,
        )
        if jr.returncode == 0 and jr.stdout.strip():
            javap_parts.append(jr.stdout)
        # Clean up the .class from the container
        _docker(["exec", CONTAINER, "rm", "-f", cp], capture_output=True)

    return "\n".join(javap_parts), dynamic_hits


# ---------------------------------------------------------------------------
# Source compatibility fixes applied before deploying to Jasper
# ---------------------------------------------------------------------------

def _compat_source(source: str) -> str:
    """Normalise JSP source for JDK-11 / Tomcat-10 compilation.

    Three classes of fix:
    1. charset/pageEncoding mismatch — Jasper reads by declared charset but we
       deploy as UTF-8; replace non-UTF-8 charset declarations so Jasper uses
       the same encoding we wrote.
    2. 'enum' as variable name — reserved since Java 5, rejected by JDK 11.
       Rename every bare 'enum' token to 'enumIt'.
    3. Oracle JDBC imports — oracle.jdbc is not on the Tomcat classpath; strip
       those import directives so the compile doesn't abort on missing class.
    """
    import re as _re

    # 0. Decode unicode (\uXXXX) and octal (\0-\377) escapes so later patterns
    #    can match identifiers that were written as e.g. enum (= "enum") or
    #    request.getRealPath (= "getRealPath").  Must run before all other
    #    fixes because Java compilers process these at the token level.
    source = _re.sub(r'\\u([0-9a-fA-F]{4})',
                     lambda m: chr(int(m.group(1), 16)), source)
    source = _re.sub(r'\\([0-7]{1,3})',
                     lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 128 else m.group(0),
                     source)

    # 1. Normalise charset/pageEncoding to UTF-8
    source = _re.sub(
        r'(charset\s*=\s*)(?!UTF-8|utf-8)([^\s"\'%;>]+)',
        r'\1UTF-8', source, flags=_re.I,
    )
    source = _re.sub(
        r'(pageEncoding\s*=\s*["\'])(?!UTF-8|utf-8)([^"\']+)(["\'])',
        r'\1UTF-8\3', source, flags=_re.I,
    )

    # 2. Rename 'enum' variable name (reserved keyword since Java 5)
    source = _re.sub(r'\benum\b', 'enumIt', source)

    # 3. Drop unresolvable oracle.jdbc imports (can't add driver to classpath)
    source = _re.sub(r'<%@\s*page\s+import="oracle\.jdbc[^"]*"%>\s*\n?', '', source)
    source = _re.sub(r'<%@\s*page\s+import="oracle\.[^"]*"%>\s*\n?', '', source)

    # 4. request.getRealPath() removed in Jakarta Servlet 5.0 (Tomcat 10+);
    #    use getServletContext().getRealPath() instead
    source = _re.sub(r'\brequest\.getRealPath\s*\(', 'getServletContext().getRealPath(', source)

    # 5. Invalid Java string escape sequences (e.g. \k, \p) — strip the
    #    backslash so the string literal still compiles
    source = _re.sub(r'\\([^\\btnfr"\'0-7u\n\r])', r'\1', source)

    return source


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compile_jsp(jsp_path: Path) -> tuple[str, list[str]]:
    """
    Compile a JSP and return (javap_text, dynamic_hits).

    javap_text  — javap -c -p -verbose output for the compiled class(es)
    dynamic_hits — API labels intercepted by the Java agent during execution
                   (e.g. ["api:runtime_exec", "api:file_write"])

    Raises RuntimeError if both compilation passes fail or the JSP has no
    Java scriptlet content.
    """
    ensure_tomcat()
    WEBAPPS_DIR.mkdir(parents=True, exist_ok=True)

    source = jsp_path.read_text(errors="replace")
    # Tomcat 10 uses jakarta.* — rewrite old javax.servlet/websocket references
    source = (source
              .replace("javax.servlet", "jakarta.servlet")
              .replace("javax.websocket", "jakarta.websocket"))
    source = _compat_source(source)

    # Pre-pass: if a WEB-INF/ exists near the JSP, inject it into the container
    # so Jasper can resolve app-specific classes during Pass 1.
    webinf = _find_webinf(jsp_path)
    if webinf:
        _mount_webinf(webinf)

    # Pass 1: original JSP
    javap_text, hits = _compile_one(jsp_path.name, source)
    if javap_text:
        return javap_text, hits

    # Pass 2: scriptlets only
    stripped = _strip_to_scriptlets(source)
    if stripped is None:
        raise RuntimeError(
            f"No Java scriptlet content in '{jsp_path.name}' "
            "(pure template — no executable bytecode to analyse)."
        )

    javap_text, hits = _compile_one(f"sb_{jsp_path.stem[:36]}.jsp", stripped)
    if javap_text:
        return javap_text, hits

    raise RuntimeError(
        f"JSP compilation failed for '{jsp_path.name}' on both passes "
        "(syntax error in scriptlet code, or unsupported Java features)."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(
        description="Compile a .jsp and print javap output via Docker Tomcat.")
    ap.add_argument("jsp", help=".jsp file to compile")
    args = ap.parse_args()

    jsp_path = Path(args.jsp)
    if not jsp_path.exists():
        print(f"File not found: {jsp_path}", file=sys.stderr); sys.exit(1)
    if jsp_path.suffix.lower() != ".jsp":
        print(f"Expected .jsp, got: {jsp_path.suffix}", file=sys.stderr); sys.exit(1)

    try:
        text = compile_jsp(jsp_path)
        print(text)
    except RuntimeError as e:
        print(f"  [ERROR] {e}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
