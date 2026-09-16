
from urllib.parse import unquote

from app.models.schemas import Evidence, DetectionResult


def decode_url(value):
    return unquote(value)


def is_path_traversal(path):
    decoded_path = decode_url(path)

    return "../" in decoded_path


def detect_path_traversal(
    path,
    query=None,
    method=None,
    status_code=None,
    response_size=None,
):

    decoded_path = decode_url(path)

    decoded_query = None

    if query:
        decoded_query = decode_url(query)

    values_to_check = [
        decoded_path
    ]

    if decoded_query:
        values_to_check.append(decoded_query)

    for value in values_to_check:

        if "../" not in value:
            continue

        evidence = [
            Evidence(
                type="url_decoded_path",
                value=decoded_path,
                source="path_traversal_detector",
            ),
            Evidence(
                type="path_pattern",
                value="../",
                source="path_traversal_detector",
            ),
        ]

        if decoded_query:
            evidence.append(
                Evidence(
                    type="url_decoded_query",
                    value=decoded_query,
                    source="path_traversal_detector",
                )
            )

        if method:
            evidence.append(
                Evidence(
                    type="http_method",
                    value=method,
                    source="path_traversal_detector",
                )
            )

        if status_code is not None:
            evidence.append(
                Evidence(
                    type="http_status_code",
                    value=status_code,
                    source="path_traversal_detector",
                )
            )

        if response_size is not None:
            evidence.append(
                Evidence(
                    type="http_response_size",
                    value=response_size,
                    source="path_traversal_detector",
                )
            )

        return DetectionResult(
            is_detected=True,
            detection_type="path_traversal",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )

