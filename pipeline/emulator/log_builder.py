from pydantic import BaseModel, field_validator
from typing import Optional

_HIVE_ALIASES: dict[str, str] = {
    "HKCU\\":  "HKEY_CURRENT_USER\\",
    "HKLM\\":  "HKEY_LOCAL_MACHINE\\",
    "HKCR\\":  "HKEY_CLASSES_ROOT\\",
    "HKU\\":   "HKEY_USERS\\",
    "HKCC\\":  "HKEY_CURRENT_CONFIG\\",
    # forward-slash variants (defensive)
    "HKCU/":   "HKEY_CURRENT_USER/",
    "HKLM/":   "HKEY_LOCAL_MACHINE/",
    "HKCR/":   "HKEY_CLASSES_ROOT/",
    "HKU/":    "HKEY_USERS/",
    "HKCC/":   "HKEY_CURRENT_CONFIG/",

}


class LogEvent(BaseModel):
    # Required
    timestamp: str
    host: str
    user: str
    EventID: int
    event_type: str
    # static for Sigma compatibility
    Channel: str = "Microsoft-Windows-Sysmon/Operational"

    # Optional — Sysmon field names
    Image: Optional[str] = None
    CommandLine: Optional[str] = None
    ParentImage: Optional[str] = None
    ParentCommandLine: Optional[str] = None
    ProcessId: Optional[str] = None
    ParentProcessId: Optional[str] = None
    TargetObject: Optional[str] = None
    Details: Optional[str] = None
    SourceIp: Optional[str] = None
    DestinationIp: Optional[str] = None
    DestinationHostname: Optional[str] = None
    DestinationPort: Optional[int] = None
    OriginalFileName: Optional[str] = None
    CurrentDirectory: Optional[str] = None
    IntegrityLevel:   Optional[str] = None
    Protocol:         Optional[str] = None
    Initiated:        Optional[str] = None

    class Config:
        extra = "forbid"  # unknown fields = hard reject, not silent drop

    @field_validator("TargetObject", mode="before")
    @classmethod
    def _normalize_hive(cls, v: str | None) -> str | None:
        if not isinstance(v, str):
            return v
        for alias, full in _HIVE_ALIASES.items():
            if v.upper().startswith(alias.upper()):
                return full + v[len(alias):]
        return v
