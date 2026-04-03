from pydantic import BaseModel
from typing import Optional


class LogEvent(BaseModel):
    # Required
    timestamp: str
    host: str
    user: str
    EventID: int
    event_type: str

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

    class Config:
        extra = "forbid"  # unknown fields = hard reject, not silent drop
