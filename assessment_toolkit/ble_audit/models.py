"""Shared data structures for the BLE Security Assessment Framework."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class DiscoveredDevice:
    """One device seen during the passive scan phase."""
    address: str
    name: str | None
    rssi: int | None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, str] = field(default_factory=dict)  # company_id -> hex payload
    service_data: dict[str, str] = field(default_factory=dict)       # uuid -> hex payload
    tx_power: int | None = None
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "service_uuids": self.service_uuids,
            "manufacturer_data": self.manufacturer_data,
            "service_data": self.service_data,
            "tx_power": self.tx_power,
            "first_seen": self.first_seen,
        }


@dataclass
class CharacteristicInfo:
    """One GATT characteristic found during enumeration."""
    uuid: str
    handle: int
    properties: list[str]          # e.g. ["read", "write", "notify"]
    service_uuid: str
    descriptor_uuids: list[str] = field(default_factory=list)
    value_preview: str | None = None   # hex of the bytes read (None if not read)
    value_text: str | None = None      # human-readable decode of the value, if printable
    name: str | None = None            # friendly label for known GATT UUIDs

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "handle": self.handle,
            "properties": self.properties,
            "service_uuid": self.service_uuid,
            "descriptor_uuids": self.descriptor_uuids,
            "value_preview": self.value_preview,
            "value_text": self.value_text,
        }


@dataclass
class ServiceInfo:
    uuid: str
    handle: int
    name: str | None = None            # friendly label for known GATT services
    characteristics: list[CharacteristicInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "handle": self.handle,
            "characteristics": [c.to_dict() for c in self.characteristics],
        }


@dataclass
class Finding:
    """One classified vulnerability tied to a specific characteristic."""
    finding_id: str
    title: str
    severity: Severity
    characteristic_uuid: str
    service_uuid: str
    description: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "characteristic_uuid": self.characteristic_uuid,
            "service_uuid": self.service_uuid,
            "description": self.description,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class AssessmentResult:
    target_address: str
    target_name: str | None
    device: DiscoveredDevice | None
    services: list[ServiceInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "target_address": self.target_address,
            "target_name": self.target_name,
            "device": self.device.to_dict() if self.device else None,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp,
        }
