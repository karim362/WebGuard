"""Finding + Evidence — unified result structures."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class VerificationStatus(str, Enum):
    POTENTIAL = "potential"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"

class EvidenceType(str, Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    HEADER = "header"
    LOG = "log"
    SCREENSHOT = "screenshot"

@dataclass
class Evidence:
    type: EvidenceType
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    redacted: bool = True
    note: str = ""

@dataclass
class Finding:
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    target: str
    affected_url: str
    description: str
    module: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.POTENTIAL
    references: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    researcher_notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
