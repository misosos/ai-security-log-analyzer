"""Response-scoped display aliases for sensitive analysis subjects."""

from ipaddress import IPv4Address, IPv6Address, ip_address


def subject_aliases(subjects: tuple[str, ...] | list[str]) -> dict[str, str]:
    """Assign stable-in-response labels without encoding source identifiers.

    Alias stability is limited to one response. The order supplied by the
    already-established public projection determines labels; values and hashes
    of the source identifiers are never included.
    """
    if type(subjects) not in (tuple, list) or len(subjects) > 256:
        raise ValueError("Invalid public subject projection.") from None
    canonical = []
    for item in subjects:
        if type(item) is not str or not item or len(item) > 64:
            raise ValueError("Invalid public subject projection.") from None
        try:
            address = ip_address(item)
        except ValueError:
            raise ValueError("Invalid public subject projection.") from None
        if (type(address) not in (IPv4Address, IPv6Address)
                or (type(address) is IPv6Address and address.scope_id is not None)):
            raise ValueError("Invalid public subject projection.") from None
        canonical.append((item, str(address)))
    ordered = tuple(dict.fromkeys(value for _, value in canonical))
    result = {}
    canonical_aliases = {}
    for index, subject in enumerate(ordered):
        label = chr(ord("A") + index) if index < 26 else str(index + 1)
        canonical_aliases[subject] = f"대상 {label}"
    for original, subject in canonical:
        result[original] = canonical_aliases[subject]
    return result
