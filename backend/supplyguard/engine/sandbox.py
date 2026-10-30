"""격리 컨테이너 실행 (기획서 4.4 샌드박스, 구현 계획 M1).

digest 고정 이미지 · 비root · 입력 읽기 전용 · 네트워크 없음 · 루트 파일시스템 읽기 전용 · 권한 전부 제거 ·
CPU·메모리·시간 제한 · 환경변수는 명시한 것만(비밀 미주입).
"""
import os

import docker
from docker.errors import ImageNotFound

from .. import config


class SandboxError(RuntimeError):
    pass


def run(tool: str, args: list[str], mounts: dict[str, str], env: dict | None = None, timeout: int = 600,
        mem: str = "2g", cpus: float = 2.0) -> tuple[bytes, dict]:
    """mounts: {호스트 경로: 컨테이너 경로} 전부 읽기 전용. 반환: (stdout, 실행 기록용 정보)"""
    image = config.IMAGES[tool]
    c = docker.from_env()
    try:
        c.images.get(image)
    except ImageNotFound:
        c.images.pull(image)
    ctr = c.containers.run(
        image, args, detach=True, network_mode="none", read_only=True, tmpfs={"/tmp": "rw,mode=1777,size=512m"},
        user=f"{os.getuid()}:{os.getgid()}" if os.getuid() else "65534:65534", cap_drop=["ALL"],  # compose 안(root)에서는 nobody security_opt=["no-new-privileges"],
        mem_limit=mem, nano_cpus=int(cpus * 1e9), pids_limit=512, environment={"HOME": "/tmp", **(env or {})},
        volumes={h: {"bind": p, "mode": "ro"} for h, p in mounts.items()},
    )
    try:
        try:
            code = ctr.wait(timeout=timeout)["StatusCode"]
        except Exception as e:
            ctr.kill()
            raise SandboxError(f"{tool} 시간 초과({timeout}s)") from e
        out = ctr.logs(stdout=True, stderr=False)
        err = ctr.logs(stdout=False, stderr=True).decode(errors="replace")[-2000:]
    finally:
        ctr.remove(force=True)
    info = {"tool": tool, "image": image, "exit_code": code, "network": "none", "user": "non-root"}
    return out, info | {"stderr_tail": err, "_code": code}
