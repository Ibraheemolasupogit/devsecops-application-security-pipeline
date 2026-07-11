"""Generate a short-lived local development JWT.

This script uses synthetic keys under tests/fixtures/keys and predefined demo
identities only. It is not a production identity provider.
"""

import argparse

from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.security.authentication.dev_tokens import (
    DEMO_IDENTITIES,
    issue_dev_token,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", choices=sorted(DEMO_IDENTITIES), required=True)
    parser.add_argument("--role", choices=[role.value for role in ActorRole], action="append")
    parser.add_argument("--expires-in-seconds", type=int, default=300)
    args = parser.parse_args()
    roles = tuple(ActorRole(role) for role in args.role) if args.role else None
    print(
        issue_dev_token(
            subject=args.subject,
            roles=roles,
            expires_in_seconds=args.expires_in_seconds,
        )
    )


if __name__ == "__main__":
    main()
