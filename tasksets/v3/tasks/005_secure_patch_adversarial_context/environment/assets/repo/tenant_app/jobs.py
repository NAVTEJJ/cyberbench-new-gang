from __future__ import annotations


def run_export_job(job: dict, signer, storage, datasets: dict, audit, now: int = 0, revoked_grant_ids=None) -> dict:
    tenant_id = job["tenant_id"]
    rows = list(datasets[tenant_id])
    key = storage.put_export(tenant_id, job["export_id"], {"tenant_id": tenant_id, "rows": rows})
    audit.record("export_job_completed", job_id=job.get("job_id"), tenant_id=tenant_id, object_key=key)
    return {"tenant_id": tenant_id, "export_id": job["export_id"], "object_key": key, "row_count": len(rows)}
