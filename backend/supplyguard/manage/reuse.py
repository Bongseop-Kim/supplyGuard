"""판정 재사용·무효화 (기획서 4.10.2).

재사용 키 = (서비스, 패키지@버전, 취약점 ID). 무효화 조건 5종:
(1) 코드·lockfile 해시 변경 (2) 권고 modified 갱신 (3) KEV 신규 등재 (4) EPSS가 임계값을 넘음 (5) 예외 만료
+ (6) 취약 조건 카드 변경
사람 확정 판정은 AI가 덮어쓰지 못한다: 조건이 걸리면 AI 판정은 '제안'으로만 남고 검토 큐로 간다.

(1)의 단위(granularity):
- "service": 서비스의 코드·lockfile이 바뀌면 모든 판정을 다시 (기획서 4.10.2 초기안, 가장 보수적)
- "file"(기본): affected 판정은 인용한 근거 파일이 바뀔 때만 다시. not_affected·uncertain은 '없음'을 주장하므로
  코드·lockfile이 조금이라도 바뀌면 다시. affected를 놓치고 재사용해도 틀리는 방향이 과대 보고(안전한 쪽)다.
"""
import hashlib
from pathlib import Path

from sqlalchemy import select

from ..artifacts import digest
from .models import ExceptionRow, VerdictRow, utcnow


def basis(repo, ef, card=None) -> dict:
    return {"lockfile_hash": repo.lockfile_hash if repo else None, "code_hash": repo.code_hash if repo else None,
            "osv_modified": ef.osv_modified, "kev": bool(ef.kev), "epss": ef.epss["score"] if ef.epss else None,
            "card": digest(card)[:16] if card else None}


def reasons(old: dict, new: dict, epss_threshold: float, expired: bool = False, status: str | None = None,
            repo_path: str | None = None, granularity: str = "file") -> list[str]:
    r = []
    code_changed = (old.get("lockfile_hash"), old.get("code_hash")) != (new.get("lockfile_hash"), new.get("code_hash"))
    if code_changed and (granularity == "service" or status != "affected" or "files" not in old):  # 근거 파일 기록이 없으면 보수적으로
        r.append("코드·lockfile 변경")
    elif code_changed:
        changed = [f for f, h in (old.get("files") or {}).items() if file_sha(repo_path, f) != h]
        if changed:
            r.append(f"근거 파일 변경({', '.join(changed[:3])})")
    if old.get("osv_modified") != new.get("osv_modified"):
        r.append(f"권고 수정(modified {old.get('osv_modified')} → {new.get('osv_modified')})")
    if new.get("kev") and not old.get("kev"):
        r.append("KEV 신규 등재")
    if (old.get("epss") or 0) < epss_threshold <= (new.get("epss") or 0):
        r.append(f"EPSS 임계값 초과({old.get('epss')} → {new.get('epss')}, 임계 {epss_threshold})")
    if expired:
        r.append("예외 만료")
    if old.get("card") != new.get("card"):  # 기획서 5종 외 추가: 사내 조건 카드(지식)가 바뀌면 판정 근거가 바뀐다
        r.append("취약 조건 카드 변경")
    return r


def current(db, key: str) -> VerdictRow | None:
    """현재 유효한 공식 판정(제안 제외). 사람 판정이 있으면 그것이 우선"""
    rows = db.scalars(select(VerdictRow).where(VerdictRow.key == key, VerdictRow.valid.is_(True), VerdictRow.proposal.is_(False))
                      .order_by(VerdictRow.id.desc())).all()
    return next((r for r in rows if r.actor == "human"), rows[0] if rows else None)


def exception_expired(db, key: str, since) -> bool:
    now = utcnow()
    return db.scalar(select(ExceptionRow.id).where(ExceptionRow.finding_key == key, ExceptionRow.expires_at > since,
                                                   ExceptionRow.expires_at <= now).limit(1)) is not None


def active_exception(db, key: str) -> ExceptionRow | None:
    return db.scalar(select(ExceptionRow).where(ExceptionRow.finding_key == key, ExceptionRow.expires_at > utcnow())
                     .order_by(ExceptionRow.id.desc()).limit(1))


def file_sha(repo_path: str | None, rel: str) -> str | None:
    p = repo_path and Path(repo_path) / rel
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p and p.is_file() else None


def lookup(db, key: str, new_basis: dict, epss_threshold: float, repo_path=None, granularity="file") -> tuple[VerdictRow | None, list[str]]:
    """(현재 판정, 무효화 사유). 사유가 비어 있으면 재사용"""
    row = current(db, key)
    if not row:
        return None, []
    return row, reasons(row.basis, new_basis, epss_threshold, exception_expired(db, key, row.created_at), row.status, repo_path, granularity)
