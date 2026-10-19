from triager.advisories import Advisory


def adv(
    ghsa_id,
    packages,
    aliases=(),
    published="2025-06-01T00:00:00Z",
    package_refs=(),
    references=(),
    ranges=(),
):
    return Advisory(
        ghsa_id=ghsa_id,
        aliases=tuple(aliases),
        published=published,
        withdrawn=None,
        summary="",
        details="",
        packages=tuple(sorted(packages)),
        references=tuple(references) + tuple(package_refs),
        package_refs=tuple(package_refs),
        ranges=tuple(ranges),
    )
