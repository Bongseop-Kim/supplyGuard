"""npm semver 비교와 OSV affected 판정 (그룹 영향 열거·후보 버전에 쓴다)."""
import re

_V = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def key(v: str):
    m = _V.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    # 정식 버전이 같은 수의 프리릴리스보다 크다: (…, 1, ()) > (…, 0, (pre…))
    pre_key = (1, ()) if not pre else (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
    return (int(major), int(minor or 0), int(patch or 0), pre_key)


def cmp(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    if ka is None or kb is None:
        return (a > b) - (a < b)
    return (ka > kb) - (ka < kb)


def osv_affects(record: dict, name: str, version: str) -> bool:
    """OSV 레코드가 name@version을 영향 범위에 넣는가 (versions 목록 또는 SEMVER/ECOSYSTEM 구간)"""
    for a in record.get("affected", []):
        if a.get("package", {}).get("name") != name:
            continue
        if version in a.get("versions", []):
            return True
        for rg in a.get("ranges", []):
            if rg.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            inside = False
            for e in sorted(rg.get("events", []), key=lambda e: key(next(iter(e.values()))) or (0,)):
                if "introduced" in e:
                    if e["introduced"] == "0" or cmp(version, e["introduced"]) >= 0:
                        inside = True
                elif "fixed" in e and cmp(version, e["fixed"]) >= 0 or "last_affected" in e and cmp(version, e["last_affected"]) > 0:
                    inside = False
            if inside:
                return True
    return False


if __name__ == "__main__":
    assert cmp("1.2.10", "1.2.9") > 0 and cmp("1.0.0-beta.2", "1.0.0") < 0 and cmp("2.0.0", "2.0.0") == 0
    rec = {"affected": [{"package": {"name": "jquery"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.3"}, {"fixed": "3.5.0"}]}]}]}
    assert osv_affects(rec, "jquery", "2.2.4") and not osv_affects(rec, "jquery", "3.5.0") and not osv_affects(rec, "jquery", "1.0.0")
    print("ok")
