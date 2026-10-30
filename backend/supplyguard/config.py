"""설정: 환경변수 하나로 바꿀 수 있는 값만 둔다."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # 저장소 루트
DATA = Path(os.environ.get("SG_DATA", ROOT / "data"))
FIXTURES = ROOT / "fixtures"
DB_URL = os.environ.get("SG_DB_URL", f"sqlite:///{DATA / 'supplyguard.db'}")

# 스캐너 이미지: digest 고정 (implementation plan M1, 기획서 4.4). 바꿀 때는 docker pull 후 digest를 새로 적는다
IMAGES = {
    "syft": "anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a",
    "grype": "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea",
    "osv-scanner": "ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0",
}

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
DECISIONS_MODEL = "gpt-6-luna"  # Decisions API가 지원하는 유일한 모델
RESPONSES_MODEL = os.environ.get("SG_RESPONSES_MODEL", "gpt-6")


def ai_enabled() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY", "").strip())
