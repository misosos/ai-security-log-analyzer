"""Pinned, fixed synthetic asset delivery; no evaluation replay on request."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from fastapi import HTTPException, Request
from fastapi.responses import Response

from app.local_request_security import classify_local_request
from app.web_ui import _HEADERS

_ROOT = Path(__file__).resolve().parents[1]
_MAX_BYTES = 128 * 1024
# Explicitly reviewed file bytes and corpus manifest pins; never derived from input.
_ASSET_PIN = "9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195"
_MANIFEST_PINS = (
    (("sample_logs", "counterfactual"), "manifest.json", "a0d81f404b99e19acb15458fe80fada677dab846db79cb3682b1f7359b70d062"),
    (("sample_logs", "counterfactual_holdout"), "manifest.json", "392127d5ad7fb61cfca361d0b9c21a6c349d94313c14bd3c1f4ead48f9393739"),
)

_FIXTURE_PINS = (
    (('sample_logs', 'counterfactual'), 'bf_app_add_failure_base.log', 'fbc7c661b6e68d31a2ea4582d22ba75b9f7f7c38489ad93dc4535a7c9b20317d'),
    (('sample_logs', 'counterfactual'), 'bf_app_change_account_base.log', '2b7dddc781eecf02d6368c6dad08b26e9bc6ac26dfd143d020971e98c03c423f'),
    (('sample_logs', 'counterfactual'), 'bf_app_change_ip_base.log', '2b7dddc781eecf02d6368c6dad08b26e9bc6ac26dfd143d020971e98c03c423f'),
    (('sample_logs', 'counterfactual'), 'bf_app_exact60_reorder_base.log', '6b49e8bfce078d8413667cc96fdcf3dea3c5dc0f4998e740aa4a3e88565e6897'),
    (('sample_logs', 'counterfactual'), 'bf_app_late_timestamp_base.log', '2b7dddc781eecf02d6368c6dad08b26e9bc6ac26dfd143d020971e98c03c423f'),
    (('sample_logs', 'counterfactual'), 'bf_app_partial_account_base.log', '2b7dddc781eecf02d6368c6dad08b26e9bc6ac26dfd143d020971e98c03c423f'),
    (('sample_logs', 'counterfactual'), 'bf_app_remove_failure_base.log', '2b7dddc781eecf02d6368c6dad08b26e9bc6ac26dfd143d020971e98c03c423f'),
    (('sample_logs', 'counterfactual'), 'bf_ssh_exact60_reorder_base.log', '58c5e2b3fbe2b627bef5b85898d665a904f90c1e8a15cbdab2bd08033f10c416'),
    (('sample_logs', 'counterfactual'), 'spray_app_add_failure_base.log', 'bd2f40abd45c804015bbebcc6aadf9fd0e20390dbd20fa62f85da279dda070cb'),
    (('sample_logs', 'counterfactual'), 'spray_app_change_account_base.log', '132350eb214a9f39d254a6f97cb3ac230b5607bcd4d174406861a41fd8e474eb'),
    (('sample_logs', 'counterfactual'), 'spray_app_change_ip_base.log', '132350eb214a9f39d254a6f97cb3ac230b5607bcd4d174406861a41fd8e474eb'),
    (('sample_logs', 'counterfactual'), 'spray_app_late_timestamp_base.log', 'e1e1d91d2a3215a0db18cb1bb49cd2fa3cc8d95eca73d3a3721e83584b716842'),
    (('sample_logs', 'counterfactual'), 'spray_app_partial_account_base.log', '132350eb214a9f39d254a6f97cb3ac230b5607bcd4d174406861a41fd8e474eb'),
    (('sample_logs', 'counterfactual'), 'spray_app_remove_failure_base.log', 'bd2f40abd45c804015bbebcc6aadf9fd0e20390dbd20fa62f85da279dda070cb'),
    (('sample_logs', 'counterfactual'), 'spray_ssh_exact60_reorder_base.log', '4f0d2fadc4bfea12e363bdf6416d75988ddfe6f822831af033cb872045cb41de'),
    (('sample_logs', 'counterfactual'), 'spray_ssh_rejected_timestamp_base.log', 'ba2b0939462000afedb924987cd6ebf4faee702cc03ec959912bade0ef0ac886'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_app_61_to_60_base.log', '1b5b04e97c8347954dc149c7e992a45f14fbd25943308b876a1ef60371e219ad'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_app_partial_missing_user_base.log', 'adf6f9333a7014348946a5b9cc79db2ebac430b56362b4961933d06c420cb475'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_app_subject_membership_change_base.log', '0d2fd4b3fbb1aac729cb6986cd970aa2d045ea26f19f1e2ef0f290b51419aa93'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_app_window_with_late_ip_noise_base.log', '03607adc43c7b1173c04908e58f8cc0c965de2c80b053350c554ac69b4a34c9e'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_ssh_61_second_crossing_base.log', 'c890676cf47ca0c45616a1f69605a875024416d668bdab0c3749546785fd3df5'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_ssh_rejected_timestamp_base.log', 'dd6777707094fd0d855fc062a5e25b4ba3b71a5c0ce046c89ce7992bf54a0a87'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_bf_ssh_two_qualifying_accounts_base.log', 'f0b4bebd94355be02217ea88c276b06f93a8e6c16bf7e78f785e73b8071daa5c'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_app_absent_permutation_base.log', 'e41c23b9d1871efbadf4f531097f1964bae40cd56d19e2ad9636d26011e6a2c7'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_app_exact60_permutation_base.log', 'e36d9b5c495cbcf0947ada999740ff2471e26fb83d07ebc9f3bba8fcb35eaf84'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_app_partial_account_base.log', '8000172aa8cca6406a613715e31d7226accb39d8c5cca5d90480bcffbd7d3283'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_app_remove_boundary_base.log', '4d52296cc682d31474b772692fc8bdb1316d55e605ade9b8c1add47224f0f1db'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_app_third_account_added_base.log', '4f86f390e92fb1d0b3273c2db5dd05b75c8b09532816a751b829aecbfe2ce37f'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_ssh_fourth_failure_at60_base.log', '82f169826589c55a0f9e3e41ba80f44a6f9d5dff0f8206f1ba3d32585454ddb8'),
    (('sample_logs', 'counterfactual_holdout'), 'er1c_spray_ssh_span_61_base.log', '14f83c5c81c6c126d9c983132fc1a8ea199acd86d2037739a7d110906de5a311'),
    (('sample_logs', 'counterfactual_holdout'), 'hashes.json', '0280690f3d86ab41725bc9004e3d43ab956505eab206a56bc2d5194a4f2a50f1'),
)

_SOURCE_VERSION_PINS = (
    (('app', 'analyzer'), 'html_report.py', '479d46aa2dddcacdccd0588fd0b6d219c2e81984b0ff17998f080fcbd6dce1f3'),
    (('app', 'analyzer'), 'html_report_file.py', 'bce6e70651f158514781fd4c64ce6da5fde2746b498bbd2369d64378ed2087af'),
    (('app', 'analyzer'), 'pipeline.py', 'ce96d8ebe4ece920b8105015bfb88fb03529758635c750d4415d6669d2923061'),
    (('app', 'analyzer'), 'process_execution.py', 'eb48d173587a04be86fe4e8ce161bf624569decef482422759aafaa4c000732c'),
    (('app', 'analyzer'), 'process_execution_classification.py', '4b8112f796723e16d99d07ffd401697f42a2a73c872dee48b06425265b3b923f'),
    (('app', 'analyzer'), 'report.py', '549fbcd5bcb2f85ecdc64cc3341de6d8744c6c57b5239e213c66a5cbefb4f086'),
    (('app', 'analyzer'), 'report_projection.py', '6eccaee798efed9ea3536994bf4c8272681a8ed489b82d0be524172972dad445'),
    (('app', 'analyzer'), 'risk.py', '151a9129e7eecd4b867386a8ddfb314574ceeed9223010d91c3aa2126d222706'),
    (('app', 'analyzer'), 'web_observation_projection.py', '76b4e4a893891fee9411d72369c2f18705df3c43a3914943b5480d8f0328e433'),
    (('app', 'correlation'), 'attack_chain.py', '0535e800a5277202eb4f75fff0a4bcf33d2cf8d67642f851d0d10aaee1cf1d13'),
    (('app', 'correlation'), 'linux_audit_login_session.py', 'ac154671fe809a92968a668664500dffa68fcb40ef7c256658a749cf9b1f8779'),
    (('app', 'correlation'), 'linux_audit_session.py', '5001756faa0f26685e831adc5af4b2d051bd51b20c7a50658911daf133cd38a7'),
    (('app', 'correlation'), 'session_process.py', '635661c4dbc7affcf495f879706fa7500aebc1a2f1f1ee8e5982c7b4272fbfeb'),
    (('app', 'detector'), 'brute_force.py', 'cfcbdf431a4cf37c90a04be6fddff31a450e27101c77b389c3235403ee83407f'),
    (('app', 'detector'), 'password_spray.py', 'a47e3626c05cd8c652f2e125dc92065dae9127ab0d51fc33cf044dda10cefd56'),
    (('app', 'detector'), 'shared_memory_execution.py', '41b9a36aa9b2242e2d35c74698d56a6e1c0e79c13f6877d439ad0867aa59f0f7'),
    (('app', 'detector'), 'web_attack.py', '7c60008e756f0333feb160393b1c85e4b96468457533b9bf7c60e4a61d22ad59'),
    (('app', 'evaluation'), '__init__.py', '4b7f8d82a1c6e5a69c454a2f0a242b02347545923b9fdc6bf674b270c2171466'),
    (('app', 'evaluation'), 'counterfactual_analyst_report.py', '5d3e1ce29aec1144e70cdc4f043190494085c0f12c199b277d881943f8e1a557'),
    (('app', 'evaluation'), 'counterfactual_comparison.py', 'abd5b52b72ab2d518cb53c9699ffd0adbcc2c804be5638edfd1761c76ffd9a91'),
    (('app', 'evaluation'), 'counterfactual_corpus.py', 'c77372025520fc8f90b4897376261dabaedd213c0eee0503709dd0683ce0a7a2'),
    (('app', 'evaluation'), 'counterfactual_holdout.py', '9f0d1c564a35caf539746b194438f3953c3d4da7238e1c328b071a2afd3553e0'),
    (('app', 'evaluation'), 'counterfactual_mutation.py', '463241333c0a62fd20e8d66d50fbd963e02abb7516eed9bf46e8f4a08d3aaeb0'),
    (('app', 'evaluation'), 'counterfactual_replay.py', 'dd21cb0232aecfd64995760ce3b2b5389602f3683cff5160541a748f1282a7bc'),
    (('app', 'evaluation'), 'counterfactual_safe_projection.py', 'aff6f9075ab6081f65372e6b54e00acc037f6e72b3591bc6895abeff03736749'),
    (('app',), 'investigation_role_snapshot_36_4.py', 'b12013380209c9d26cfb2eef20f32bffa0eea6a878f0de06816aaca5b7280a42'),
    (('app', 'loader'), 'file_loader.py', '44fae72efb1dda76289fd7bdae68c2ff2809b0171185599b7c4448939ae2987a'),
    (('app', 'loader'), 'linux_audit_loader.py', 'f2f2f54d7f592dcc705a56c8d0852d2a3051491566901675b79e531df956b59a'),
    (('app',), 'main.py', 'd66ed992159a3f5e6770c9338dd23be2b15585be58c3b4d43ef734071e78f69c'),
    (('app', 'models'), 'schemas.py', '1cfee6ecb055001a63487ffc7a628130f4ef2972aba0fe8aaf32f8ac9993b6ce'),
    (('app', 'parser'), 'access_log.py', 'e33284367d23b96eaddd0cf3ea0cf91ce864c53ca327fe1c2831d1f32ee50e5b'),
    (('app', 'parser'), 'auth_log.py', 'a6360da532cfc98e02faaa70a6b45b1795d27ad202b3f43f41fa3e33d59b1132'),
    (('app', 'parser'), 'linux_audit.py', '73a873991fc497c4488994327f2757cd797fb7f45497840e4b4c04edadb45a72'),
    (('app', 'parser'), 'registry.py', 'b670de3e785fb375108dc9309426363588c5879ce1466e65dfb5651f8104c65b'),
    (('app', 'parser'), 'ssh_auth.py', '84cfa9246349e83f18524c8594eb028cdc4b86b188b6360789d286303f75f787'),
    (('app', 'parser'), 'time_utils.py', 'de75ea48f327978a56281b632936cbeb066b2b218086d3c5085abbe3ad97b694'),
    (('app',), 'public_identifiers.py', '3a1ce00163869db78b6b51a075ed4c29b4e9b5a980f6d0aec261375d55d28992'),
)


def _read_pinned(directories: tuple[str, ...], name: str, expected: str, *, allow_empty: bool = False) -> bytes:
    """Open only literal paths under anchored directories and return verified bytes."""
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root = os.open(_ROOT, flags)
        descriptors.append(root)
        current = root
        for part in directories:
            current = os.open(part, flags, dir_fd=current)
            descriptors.append(current)
        before = os.stat(name, dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_BYTES or (before.st_size == 0 and not allow_empty):
            raise OSError()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        descriptors.append(fd)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_size != before.st_size:
            raise OSError()
        chunks = []
        remaining = _MAX_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(fd)
        current_entry = os.stat(name, dir_fd=current, follow_symlinks=False)
        fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (len(content) != opened.st_size or fingerprint(before) != fingerprint(opened)
                or fingerprint(opened) != fingerprint(after) or fingerprint(after) != fingerprint(current_entry)
                or hashlib.sha256(content).hexdigest() != expected):
            raise OSError()
        return content
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


async def serve_snapshot(request: Request, port: int) -> Response:
    """Deny nonlocal, cross-origin and parameterized requests before reading assets."""
    denied = HTTPException(status_code=404, detail="Not Found")
    if classify_local_request(request) is not None:
        raise denied
    server = request.scope.get("server")
    if (type(server) not in (tuple, list) or tuple(server) != ("127.0.0.1", port)
            or request.url.scheme != "http"
            or request.headers.getlist("host") != [f"127.0.0.1:{port}"]
            or request.scope.get("query_string")
            or request.headers.get("transfer-encoding") is not None):
        raise denied
    for header, allowed in (("sec-fetch-site", {"same-origin", "none"}),
                            ("sec-fetch-mode", {"same-origin", "cors"}),
                            ("sec-fetch-dest", {"empty"})):
        values = request.headers.getlist(header)
        if len(values) > 1 or (values and values[0] not in allowed):
            raise denied
    if request.headers.getlist("content-length") not in ([], ["0"]):
        raise denied
    async for chunk in request.stream():
        if chunk:
            raise denied
    try:
        for directories, name, pin in (*_MANIFEST_PINS, *_FIXTURE_PINS):
            _read_pinned(directories, name, pin)
        for directories, name, pin in _SOURCE_VERSION_PINS:
            _read_pinned(directories, name, pin, allow_empty=True)
        content = _read_pinned(("frontend",), "evaluation-snapshot-v1.json", _ASSET_PIN)
    except (OSError, ValueError, AttributeError):
        raise denied from None
    return Response(content=content, media_type="application/json; charset=utf-8", headers=_HEADERS)
