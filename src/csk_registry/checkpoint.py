"""Startup checkpoint comparison (registry-service profile §6)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .protocol import ProtocolError

if TYPE_CHECKING:
    from .store import SnapshotBoundary


RESTORE_BELOW_CHECKPOINT = "restore_below_checkpoint"
RESTORE_INCONSISTENT_WITH_CHECKPOINT = "restore_inconsistent_with_checkpoint"
CHECKPOINT_SIGNATURE_INVALID = "checkpoint_signature_invalid"
CHECKPOINT_NOT_CONFIGURED = "checkpoint_not_configured"

#: The closed refusal set of profile §6 ("No other restore-checkpoint
#: diagnostic exists"). ``checkpoint_not_configured`` is posture, recorded
#: when no checkpoint is configured, never a refusal.
REFUSAL_DIAGNOSTICS = frozenset(
    {
        RESTORE_BELOW_CHECKPOINT,
        RESTORE_INCONSISTENT_WITH_CHECKPOINT,
        CHECKPOINT_SIGNATURE_INVALID,
    }
)


@dataclass(frozen=True)
class CheckpointView:
    """Checkpoint boundary fields used by the §6 startup comparison.

    Unlike :class:`SnapshotBoundary`, ``version`` and ``log_size`` are not
    forced equal: ``registry-snapshot-v1`` permits ``log_size <= version``,
    and the equal-version rule compares ``log_size`` explicitly.
    """

    version: int
    log_size: int
    head: str
    merkle_root: str
    created_at: str

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> CheckpointView:
        version = snapshot.get("version")
        log_size = snapshot.get("log_size")
        head = snapshot.get("head")
        merkle_root = snapshot.get("merkle_root")
        created_at = snapshot.get("created_at")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or not isinstance(log_size, int)
            or isinstance(log_size, bool)
            or not isinstance(head, str)
            or not isinstance(merkle_root, str)
            or not isinstance(created_at, str)
        ):
            raise ProtocolError("snapshot checkpoint boundary is malformed")
        return cls(
            version=version,
            log_size=log_size,
            head=head,
            merkle_root=merkle_root,
            created_at=created_at,
        )


def compare_checkpoint(
    live: SnapshotBoundary,
    checkpoint: CheckpointView,
    prefix: SnapshotBoundary | None,
) -> str | None:
    """Compare the verified live boundary against a verified §6 checkpoint.

    ``prefix`` is the live boundary at ``checkpoint.log_size`` (the R2
    ``boundaries`` row), or ``None`` when that prefix is unavailable.
    Returns ``None`` when the live state may serve, otherwise the refusal
    diagnostic: live below the checkpoint is
    ``restore_below_checkpoint``; an equal version with a different
    ``head``, ``merkle_root`` or ``log_size``, or a live state above the
    checkpoint whose log does not reproduce the checkpoint head and Merkle
    root at its ``log_size``, is ``restore_inconsistent_with_checkpoint``.
    """
    if live.version < checkpoint.version or live.log_size < checkpoint.log_size:
        return RESTORE_BELOW_CHECKPOINT
    if live.version == checkpoint.version:
        if (
            live.head == checkpoint.head
            and live.merkle_root == checkpoint.merkle_root
            and live.log_size == checkpoint.log_size
        ):
            return None
        return RESTORE_INCONSISTENT_WITH_CHECKPOINT
    if (
        prefix is not None
        and prefix.head == checkpoint.head
        and prefix.merkle_root == checkpoint.merkle_root
    ):
        return None
    return RESTORE_INCONSISTENT_WITH_CHECKPOINT
