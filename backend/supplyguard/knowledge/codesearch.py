"""대상 코드 에이전틱 검색 도구 (기획서 4.8: 색인 없이 grep·파일 범위 읽기). 신뢰 등급 T2 — 증거 전용.

읽기 전용이고 저장소 밖으로 나가지 못한다. node_modules·빌드 산출물·압축 번들은 앱 코드가 아니므로 뺀다.
"""
import hashlib
import re
import subprocess
from pathlib import Path

from ..artifacts import Snippet

EXCLUDE = ["!node_modules", "!**/node_modules/**", "!public/**", "!dist/**", "!build/**", "!*.min.js", "!**/bundle.js", "!.git"]
CODE_GLOBS = ["*.js", "*.cjs", "*.mjs", "*.ts", "*.tsx", "*.jsx", "*.ejs", "*.hbs", "*.dust", "*.pug", "*.html", "*.vue", "*.svelte"]


def _safe(repo: str, rel: str) -> Path:
    root = Path(repo).resolve()
    p = (root / rel).resolve()
    if root != p and root not in p.parents:
        raise PermissionError(f"저장소 밖 경로: {rel}")
    return p


def search(repo: str, pattern: str, globs=CODE_GLOBS, limit: int = 60) -> list[Snippet]:
    args = ["rg", "-n", "--no-heading", "-e", pattern]
    for g in [*globs, *EXCLUDE]:
        args += ["-g", g]
    r = subprocess.run([*args, "."], cwd=repo, capture_output=True, text=True, timeout=30)
    out = []
    for line in r.stdout.splitlines()[:limit]:
        f, ln, text = line.split(":", 2)
        out.append(Snippet(file=f.removeprefix("./"), line=int(ln), text=text.strip()[:300]))
    return out


def read(repo: str, rel: str, start: int, end: int) -> list[str]:
    lines = _safe(repo, rel).read_text(errors="replace").splitlines()
    return lines[max(0, start - 1):min(len(lines), end, start + 199)]


def imports(repo: str, package: str) -> list[Snippet]:
    """require('pkg'), require('pkg/sub'), import … from 'pkg'"""
    q = re.escape(package)
    pat = rf"""(require\(\s*['"]{q}(/[^'"]*)?['"]\s*\)|from\s+['"]{q}(/[^'"]*)?['"]|import\s+['"]{q}(/[^'"]*)?['"])"""
    return [s.model_copy(update={"symbol": package}) for s in search(repo, pat)]


def references(repo: str, package: str) -> list[Snippet]:
    """import 말고 다른 경로의 사용: package.json scripts(번들링 등), 빌드 설정, 템플릿의 script 태그.
    의존성 선언 줄("pkg": "^1.0")은 빼고 센다"""
    q = re.escape(package)
    hits = search(repo, rf"(?:^|[^\w@/-]){q}(?:[^\w-]|$)", globs=["package.json", "*.config.js", "*.config.ts", "*.html", "*.ejs", "*.hbs"])
    return [s.model_copy(update={"symbol": package}) for s in hits if not re.match(rf'\s*"{q}"\s*:', s.text)]


def code_hash(repo: str) -> str:
    """판정 근거가 되는 파일(앱 코드·템플릿·package.json) 내용 해시. 판정 재사용 무효화 조건 (1)에 쓴다"""
    args = ["rg", "--files"]
    for g in [*CODE_GLOBS, "package.json", *EXCLUDE]:
        args += ["-g", g]
    files = sorted(subprocess.run([*args, "."], cwd=repo, capture_output=True, text=True, timeout=30).stdout.split())
    h = hashlib.sha256()
    for f in files:
        h.update(f.encode() + b"\0" + hashlib.sha256((Path(repo) / f).read_bytes()).digest())
    return h.hexdigest()


def line_at(repo: str, rel: str, line: int) -> str | None:
    try:
        lines = _safe(repo, rel).read_text(errors="replace").splitlines()
    except (OSError, PermissionError):
        return None
    return lines[line - 1] if 0 < line <= len(lines) else None
