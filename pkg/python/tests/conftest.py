"""Every proxy test runs on both servers: the standard library's and uvicorn
(when installed), which share all the proxy's code above HTTP."""

from __future__ import annotations

import importlib.util

import pytest

SERVERS = ["standard"] + (["uvicorn"] if importlib.util.find_spec("uvicorn") else [])


@pytest.fixture(params=SERVERS)
def server_kind(request):
    return request.param
