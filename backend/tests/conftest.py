import os
import tempfile

os.environ["SG_DATA"] = tempfile.mkdtemp(prefix="sg-test-")
os.environ.pop("OPENAI_API_KEY", None)  # 테스트는 외부 호출 없이. LLM은 가짜 응답으로 바꿔 끼운다

import pytest

from supplyguard import config
from supplyguard.manage import models


@pytest.fixture()
def db():
    models.init(f"sqlite:///{config.DATA}/t{os.getpid()}-{tempfile.mktemp(dir='').strip('/')}.db")
    s = models.session()
    yield s
    s.close()
