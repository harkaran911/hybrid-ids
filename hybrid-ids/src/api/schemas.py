from pydantic import BaseModel
from typing import Optional, Dict, Any

class AlertOut(BaseModel):
    id: int
    time: str
    alert_type: str
    severity: str
    confidence: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    evidence_json: Dict[str, Any]

class HealthOut(BaseModel):
    status: str