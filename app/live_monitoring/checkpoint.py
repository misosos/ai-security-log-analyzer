"""Private, bounded same-file restart checkpoint for the default v2 config.

Only the default local launcher may construct this manager. It contains byte
positions and OS file identity, never a copy or fingerprint of raw log data.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

try:
    import fcntl
except ImportError:  # Windows is not a supported checkpoint platform.
    fcntl = None

from app.live_monitoring.config import LiveMonitorConfigV2, _open_regular
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.default_config import _open_parent
from app.live_monitoring.parser_adapter import parse_live_records


MAX_CHECKPOINT_BYTES = 8192
MAX_REPLAY_BYTES = 256 * 1024
MAX_REPLAY_RECORDS = 256
CHECKPOINT_NAME = "checkpoint-source-000001.json"
LOCK_NAME = "checkpoint-source-000001.lock"
_FIELDS = frozenset({
    "schema_version", "config_schema_version", "source_id", "source_role",
    "start_position", "parser_timezone", "checkpoint_policy", "file_device",
    "file_inode", "replay_start_offset", "committed_offset", "committed_file_size",
    "write_sequence", "batches", "history_count", "history_bytes",
    "partial_line_present", "semantic_digest",
})
_MESSAGES = {
    "CHECKPOINT_UNSAFE": "복구 자료의 소유자·권한·형식을 확인하십시오.",
    "CHECKPOINT_CORRUPT": "복구 자료가 손상되었습니다. 자동으로 새 위치에서 시작하지 않습니다.",
    "CHECKPOINT_SOURCE_CHANGED": "로그 파일이 바뀌어 자동 복구하지 않습니다.",
    "CHECKPOINT_REPLAY_LIMIT": "재생 범위 상한에 도달했습니다. 자동 복구하지 않습니다.",
    "CHECKPOINT_REPLAY_MISMATCH": "재생 결과가 저장된 상태와 일치하지 않습니다.",
    "CHECKPOINT_WRITE_FAILED": "마지막 처리 위치를 저장하지 못했습니다. 모니터링을 중단하십시오.",
    "CHECKPOINT_ALREADY_OWNED": "다른 로컬 모니터링 프로세스가 사용 중입니다.",
}


class LiveCheckpointError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in _MESSAGES else "CHECKPOINT_CORRUPT"
        super().__init__(f"{self.code}: {_MESSAGES[self.code]}")

    def __repr__(self) -> str:
        return f"LiveCheckpointError(code={self.code!r})"


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in items:
        if key in result:
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise LiveCheckpointError("CHECKPOINT_CORRUPT")


@dataclass(frozen=True, slots=True, repr=False)
class Checkpoint:
    schema_version: str
    config_schema_version: str
    source_id: str
    source_role: str
    start_position: str
    parser_timezone: str
    checkpoint_policy: str
    file_device: int
    file_inode: int
    replay_start_offset: int
    committed_offset: int
    committed_file_size: int
    write_sequence: int
    batches: tuple[int, ...]
    history_count: int
    history_bytes: int
    partial_line_present: bool
    semantic_digest: str

    def __post_init__(self) -> None:
        numbers = (self.file_device, self.file_inode, self.replay_start_offset,
                   self.committed_offset, self.committed_file_size, self.write_sequence,
                   self.history_count, self.history_bytes)
        if (self.schema_version != "1" or self.config_schema_version != "2"
            or self.source_id != "SOURCE-000001" or self.source_role != "application"
            or self.start_position != "FROM_END" or self.parser_timezone != "Asia/Seoul"
            or self.checkpoint_policy != "BOUNDED_REPLAY_V1"
            or any(type(n) is not int or n < 0 for n in numbers)
            or type(self.batches) is not tuple
            or any(type(n) is not int or not 1 <= n <= 16 for n in self.batches)
            or len(self.batches) != self.write_sequence
            or sum(self.batches) > MAX_REPLAY_RECORDS
            or self.committed_offset < self.replay_start_offset
            or self.committed_file_size < self.committed_offset
            or self.committed_offset - self.replay_start_offset > MAX_REPLAY_BYTES
            or not 0 <= self.history_count <= MAX_REPLAY_RECORDS
            or not 0 <= self.history_bytes <= MAX_REPLAY_BYTES
            or type(self.partial_line_present) is not bool
            or type(self.semantic_digest) is not str or len(self.semantic_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in self.semantic_digest)):
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")

    def __repr__(self) -> str:
        return "Checkpoint(<private>)"

    def document(self) -> dict[str, object]:
        value = asdict(self)
        value["batches"] = list(self.batches)
        return value


def _semantic_digest(worker) -> str:
    detection = worker._accumulator.snapshot()
    analysis = worker._analysis.snapshot()
    safe = {
        "detection": asdict(detection),
        "analysis": asdict(analysis),
    }
    # Repr and generic JSON of the checkpoint contain only this safe digest.
    encoded = json.dumps(safe, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class LiveCheckpointManager:
    __slots__ = ("_path", "_parent_fd", "_lock_fd", "_checkpoint", "_config", "_closed", "_readonly")

    def __init__(self, default_config_path: Path, config: LiveMonitorConfigV2, *, readonly: bool = False):
        if (type(config) is not LiveMonitorConfigV2
            or config.checkpoint_policy != "BOUNDED_REPLAY_V1"):
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
            raise LiveCheckpointError("CHECKPOINT_UNSAFE")
        self._path = default_config_path.parent / CHECKPOINT_NAME
        self._config = config
        self._parent_fd = -1
        self._lock_fd = -1
        self._checkpoint = None
        self._closed = False
        self._readonly = readonly
        try:
            self._parent_fd = _open_parent(self._path)
            if not readonly:
                self._lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                                        os.O_CLOEXEC, 0o600, dir_fd=self._parent_fd)
                locked = os.fstat(self._lock_fd)
                if (not stat.S_ISREG(locked.st_mode) or locked.st_uid != os.geteuid()
                    or locked.st_mode & 0o777 != 0o600):
                    raise LiveCheckpointError("CHECKPOINT_UNSAFE")
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise LiveCheckpointError("CHECKPOINT_ALREADY_OWNED") from None
            self._checkpoint = self._read_optional()
        except LiveCheckpointError:
            self.close()
            raise
        except Exception:
            self.close()
            raise LiveCheckpointError("CHECKPOINT_UNSAFE") from None

    def __repr__(self) -> str:
        return f"LiveCheckpointManager(closed={self._closed})"

    @property
    def committed_offset(self) -> int | None:
        return self._checkpoint.committed_offset if self._checkpoint else None

    def _read_optional(self) -> Checkpoint | None:
        try:
            named = os.stat(CHECKPOINT_NAME, dir_fd=self._parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise LiveCheckpointError("CHECKPOINT_UNSAFE") from None
        if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.geteuid()
            or named.st_mode & 0o777 != 0o600 or named.st_size > MAX_CHECKPOINT_BYTES):
            raise LiveCheckpointError("CHECKPOINT_UNSAFE")
        fd = -1
        try:
            fd = os.open(CHECKPOINT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         os.O_CLOEXEC,
                         dir_fd=self._parent_fd)
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_size) != (
                named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_size):
                raise LiveCheckpointError("CHECKPOINT_UNSAFE")
            raw = os.read(fd, MAX_CHECKPOINT_BYTES + 1)
            if len(raw) > MAX_CHECKPOINT_BYTES or len(raw) != opened.st_size:
                raise LiveCheckpointError("CHECKPOINT_UNSAFE")
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                                parse_constant=_constant)
            if type(parsed) is not dict or set(parsed) != _FIELDS or type(parsed["batches"]) is not list:
                raise LiveCheckpointError("CHECKPOINT_CORRUPT")
            parsed["batches"] = tuple(parsed["batches"])
            checkpoint = Checkpoint(**parsed)
            if (checkpoint.source_id != self._config.source_id
                or checkpoint.parser_timezone != self._config.parser_timezone):
                raise LiveCheckpointError("CHECKPOINT_CORRUPT")
            return checkpoint
        except LiveCheckpointError:
            raise
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_CORRUPT") from None
        finally:
            if fd >= 0:
                os.close(fd)

    def _write(self, checkpoint: Checkpoint) -> None:
        if self._readonly or self._closed:
            raise LiveCheckpointError("CHECKPOINT_UNSAFE")
        prior = self._read_optional()
        if prior is not self._checkpoint and prior != self._checkpoint:
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        raw = (json.dumps(checkpoint.document(), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise LiveCheckpointError("CHECKPOINT_REPLAY_LIMIT")
        name = ".checkpoint-" + secrets.token_hex(8)
        fd = -1
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=self._parent_fd)
            os.fchmod(fd, 0o600)
            if os.fstat(fd).st_mode & 0o777 != 0o600:
                raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
                view = view[count:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(name, CHECKPOINT_NAME, src_dir_fd=self._parent_fd,
                       dst_dir_fd=self._parent_fd)
            name = ""
            os.fsync(self._parent_fd)
            self._checkpoint = checkpoint
            if self._read_optional() != checkpoint:
                raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
        except LiveCheckpointError:
            raise
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED") from None
        finally:
            if fd >= 0:
                os.close(fd)
            if name:
                try:
                    os.unlink(name, dir_fd=self._parent_fd)
                except OSError:
                    pass

    def initialize_or_restore(self, worker) -> None:
        session = worker._session
        if session.source_role != "application" or worker._analysis is None:
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        try:
            session._probe_identity()
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED") from None
        opened = os.fstat(session._fd)
        if (opened.st_dev, opened.st_ino) != session._identity:
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED")
        checkpoint = self._checkpoint
        if checkpoint is None:
            start = session._offset
            initial = Checkpoint("1", "2", self._config.source_id, "application", "FROM_END",
                                 self._config.parser_timezone, "BOUNDED_REPLAY_V1",
                                 opened.st_dev, opened.st_ino, start, start, opened.st_size,
                                 0, (), 0, 0, False, _semantic_digest(worker))
            self._write(initial)
            return
        if ((opened.st_dev, opened.st_ino) != (checkpoint.file_device, checkpoint.file_inode)
            or opened.st_size < checkpoint.committed_file_size
            or session._offset != checkpoint.committed_offset):
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED")
        length = checkpoint.committed_offset - checkpoint.replay_start_offset
        if length > MAX_REPLAY_BYTES:
            raise LiveCheckpointError("CHECKPOINT_REPLAY_LIMIT")
        try:
            raw = os.pread(session._fd, length, checkpoint.replay_start_offset)
        except OSError:
            raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH") from None
        try:
            session._probe_identity()
            after_read = os.fstat(session._fd)
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED") from None
        if ((after_read.st_dev, after_read.st_ino) != (checkpoint.file_device, checkpoint.file_inode)
            or after_read.st_size < checkpoint.committed_file_size):
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED")
        if len(raw) != length or (raw and not raw.endswith(b"\n")):
            raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH")
        lines = raw.split(b"\n")[:-1] if raw else []
        if len(lines) != sum(checkpoint.batches):
            raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH")
        records = []
        offset = checkpoint.replay_start_offset
        try:
            for sequence, line in enumerate(lines, 1):
                offset += len(line) + 1
                if len(line) > 2048 or b"\x00" in line or b"\r" in line[:-1]:
                    raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH")
                payload = (line[:-1] if line.endswith(b"\r") else line).decode("utf-8")
                records.append(LiveTailRecord("application", sequence, payload,
                                              len(payload.encode("utf-8")), end_offset=offset))
            index = 0
            for count in checkpoint.batches:
                batch = parse_live_records("application", tuple(records[index:index + count]))
                index += count
                detection = worker._accumulator.prepare(batch)
                analysis = worker._analysis.prepare(detection)
                worker._accumulator.commit_prepared(detection)
                worker._analysis.commit(analysis)
            if (worker._accumulator.snapshot().history_record_count != checkpoint.history_count
                or worker._accumulator.snapshot().history_byte_count != checkpoint.history_bytes
                or _semantic_digest(worker) != checkpoint.semantic_digest):
                raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH")
            from dataclasses import replace
            publication = worker._publication
            detection_snapshot = worker._accumulator.snapshot()
            analysis_snapshot = worker._analysis.snapshot()
            publication._state = replace(
                publication._state, latest_revision=detection_snapshot.revision,
                active_observation_count=detection_snapshot.active_observation_count,
                last_counts=(detection_snapshot.total_parsed, detection_snapshot.total_ignored,
                             detection_snapshot.total_rejected), analysis=analysis_snapshot)
            worker._last_acc_snapshot = detection_snapshot
            worker._last_analysis_snapshot = analysis_snapshot
            worker._last_committed_revision = detection_snapshot.revision
            worker._revision = detection_snapshot.revision
            worker._successful = detection_snapshot.revision
            worker._parsed = detection_snapshot.total_parsed
            worker._ignored = detection_snapshot.total_ignored
            worker._rejected = detection_snapshot.total_rejected
            worker._acknowledged = sum(checkpoint.batches)
            session._next_sequence = sum(checkpoint.batches) + 1
            session._processed = sum(checkpoint.batches)
            session._acknowledged = sum(checkpoint.batches)
        except LiveCheckpointError:
            raise
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_REPLAY_MISMATCH") from None

    def prevalidate_step(self, end_offset: int | None, record_count: int) -> None:
        checkpoint = self._checkpoint
        if (checkpoint is None or type(end_offset) is not int or type(record_count) is not int
            or not 1 <= record_count <= 16 or end_offset <= checkpoint.committed_offset
            or end_offset - checkpoint.replay_start_offset > MAX_REPLAY_BYTES
            or sum(checkpoint.batches) + record_count > MAX_REPLAY_RECORDS):
            raise LiveCheckpointError("CHECKPOINT_REPLAY_LIMIT")

    def commit_step(self, worker, end_offset: int, record_count: int) -> None:
        self.prevalidate_step(end_offset, record_count)
        prior = self._checkpoint
        session = worker._session
        if session._acked_offset != end_offset:
            raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
        try:
            session._probe_identity()
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED") from None
        opened = os.fstat(session._fd)
        if ((opened.st_dev, opened.st_ino) != (prior.file_device, prior.file_inode)
            or opened.st_size < prior.committed_file_size):
            raise LiveCheckpointError("CHECKPOINT_SOURCE_CHANGED")
        snapshot = worker._accumulator.snapshot()
        checkpoint = Checkpoint(
            "1", "2", prior.source_id, "application", "FROM_END", prior.parser_timezone,
            "BOUNDED_REPLAY_V1", opened.st_dev, opened.st_ino, prior.replay_start_offset,
            end_offset, opened.st_size, prior.write_sequence + 1,
            prior.batches + (record_count,), snapshot.history_record_count,
            snapshot.history_byte_count, bool(session._partial), _semantic_digest(worker))
        self._write(checkpoint)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1
        if self._parent_fd >= 0:
            os.close(self._parent_fd)
            self._parent_fd = -1

    def delete_after_config(self) -> None:
        """Delete one validated checkpoint after its config is removed.

        A crash between the two unlinks leaves an orphan, never an active
        config silently starting at EOF. New setup refuses that orphan.
        """
        if self._closed or self._read_optional() != self._checkpoint:
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        if self._checkpoint is None:
            return
        try:
            os.unlink(CHECKPOINT_NAME, dir_fd=self._parent_fd)
            os.fsync(self._parent_fd)
            if self._read_optional() is not None:
                raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
            self._checkpoint = None
        except LiveCheckpointError:
            raise
        except Exception:
            raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED") from None
