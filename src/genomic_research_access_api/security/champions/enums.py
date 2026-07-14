"""Enumerations for the Security Champions programme."""

from typing import Literal

ChampionStatus = Literal["active", "onboarding", "inactive", "vacant"]
OnboardingStatus = Literal["complete", "in_progress", "not_started", "not_applicable"]
MaturityLevel = Literal["level_0", "level_1", "level_2", "level_3", "level_4"]
EscalationLevel = Literal[
    "squad_handling",
    "champion_escalation",
    "engineering_lead_escalation",
    "product_security_escalation",
    "risk_owner_escalation",
]
