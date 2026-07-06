"""OSS retention gate notes (Stage C)."""

from campaignfuse.stage_c import retention_status, stage_c_ready

RETENTION_REQUIRED = ">=3 external labs × 2 unprompted runs"
PUBLIC_PACKAGE_OMITS = [
    "drafts/actions destructive verbs",
    "actuators",
    "contain executors",
]

__all__ = [
    "RETENTION_REQUIRED",
    "PUBLIC_PACKAGE_OMITS",
    "retention_status",
    "stage_c_ready",
]
