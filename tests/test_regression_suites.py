import asyncio

import httpx

from agentblackbox.suites import execute_suite, suite_junit
from api.app.config import Settings
from api.app.main import create_app

HEADERS = {"X-API-Key": "suite-key"}


def test_local_suite_statuses_and_junit():
    report = execute_suite({
        "name": "portable",
        "test_cases": [
            {"name": "passed", "baseline_events": [{"event_type": "ok"}],
             "candidate_events": [{"event_type": "ok"}]},
            {"name": "changed", "baseline_events": [{"event_type": "old"}],
             "candidate_events": [{"event_type": "new"}]},
        ],
    })
    assert report["counts"] == {"passed": 1, "changed": 1, "failed": 0, "errored": 0}
    assert report["status"] == "changed"
    xml = suite_junit(report)
    assert "<testsuite" in xml
    assert "<skipped" in xml


def test_suite_api_create_run_and_approve(tmp_path):
    app = create_app(
        Settings(api_key="suite-key", database_url=f"sqlite:///{tmp_path / 'suite.db'}")
    )

    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            session = await client.post(
                "/v1/sessions", headers=HEADERS, json={"name": "suite source"}
            )
            session_id = session.json()["id"]
            case = await client.post(
                "/v1/test-cases", headers=HEADERS,
                json={"session_id": session_id, "name": "editable case"},
            )
            case_id = case.json()["id"]
            suite = await client.post(
                "/v1/test-suites", headers=HEADERS,
                json={"name": "refund suite", "test_case_ids": [case_id]},
            )
            assert suite.status_code == 201
            suite_id = suite.json()["id"]

            suite_run = await client.post(
                f"/v1/test-suites/{suite_id}/runs", headers=HEADERS, json={"candidates": {}}
            )
            assert suite_run.status_code == 201
            assert suite_run.json()["status"] == "passed"

            run_id = suite_run.json()["test_run_ids"][0]
            approved = await client.post(
                f"/v1/test-runs/{run_id}/approve", headers=HEADERS,
                json={"approved_by": "reviewer"},
            )
            assert approved.status_code == 200
            assert approved.json()["approved_by"] == "reviewer"

            junit = await client.get(
                f"/v1/test-suites/{suite_id}/runs/{suite_run.json()['id']}/junit",
                headers=HEADERS,
            )
            assert junit.status_code == 200
            assert junit.headers["content-type"].startswith("application/xml")

    asyncio.run(run())
