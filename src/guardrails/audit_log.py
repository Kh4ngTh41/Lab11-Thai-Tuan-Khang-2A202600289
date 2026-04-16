"""
Lab 11 — Audit Log & Monitoring/Alerting
Records every interaction and fires alerts on anomalies.
"""
import json
import time
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

from google.genai import types
from google.adk.plugins import base_plugin


@dataclass
class AuditEntry:
    """Single audit log entry."""
    timestamp: str
    user_id: str
    input_text: str
    output_text: str
    blocked: bool
    block_reason: Optional[str] = None
    guardrails_triggered: list = field(default_factory=list)
    latency_ms: float = 0.0
    safe_query: bool = False
    attack_query: bool = False


class AuditLogPlugin(base_plugin.BasePlugin):
    """Plugin that records every interaction for audit purposes.

    This plugin logs all inputs, outputs, and metadata to enable:
    - Security auditing
    - Compliance reporting
    - Anomaly detection
    - Performance monitoring
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        self.user_stats = defaultdict(lambda: {
            "total_requests": 0,
            "blocked_requests": 0,
            "total_latency_ms": 0.0
        })
        self.start_time = time.time()

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> types.Content | None:
        """Record input at start of request processing."""
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        input_text = self._extract_text(user_message)

        # Record start time for latency calculation
        self._current_request_start = time.time()
        self._current_input = input_text
        self._current_user_id = user_id
        self._current_guardrails = []

        return None

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ) -> types.Content:
        """Record output and complete the audit entry."""
        output_text = self._extract_text(llm_response)
        latency_ms = (time.time() - self._current_request_start) * 1000

        # Determine if request was blocked
        blocked = any(kw in output_text.lower() for kw in [
            "cannot", "block", "inappropriate", "unable",
            "sorry", "redacted", "rate limit"
        ])
        block_reason = None
        if blocked:
            if "rate limit" in output_text.lower():
                block_reason = "rate_limit"
            elif any(kw in output_text.lower() for kw in ["inject", "instruction"]):
                block_reason = "injection"
            elif any(kw in output_text.lower() for kw in ["topic", "banking"]):
                block_reason = "off_topic"
            else:
                block_reason = "content_filter"

        # Create audit entry
        entry = AuditEntry(
            timestamp=datetime.now().isoformat(),
            user_id=self._current_user_id,
            input_text=self._current_input[:500] if self._current_input else "",
            output_text=output_text[:500] if output_text else "",
            blocked=blocked,
            block_reason=block_reason,
            guardrails_triggered=self._current_guardrails,
            latency_ms=latency_ms,
            safe_query=not blocked and not any(kw in self._current_input.lower() for kw in [
                "ignore", "password", "admin", "api", "secret", "hack"
            ]),
            attack_query=any(kw in self._current_input.lower() for kw in [
                "ignore", "password", "admin", "api", "secret", "hack",
                "reveal", "system prompt", "override"
            ])
        )

        self.logs.append(entry)

        # Update user stats
        stats = self.user_stats[self._current_user_id]
        stats["total_requests"] += 1
        if blocked:
            stats["blocked_requests"] += 1
        stats["total_latency_ms"] += latency_ms

        return llm_response

    def _extract_text(self, content) -> str:
        """Extract text from Content or similar object."""
        if not content:
            return ""
        text = ""
        if hasattr(content, "parts") and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        elif hasattr(content, "text") and content.text:
            text = content.text
        return text

    def record_guardrail_trigger(self, guardrail_name: str):
        """Record that a guardrail was triggered."""
        if hasattr(self, '_current_guardrails'):
            self._current_guardrails.append(guardrail_name)

    def export_json(self, filepath: str = "audit_log.json"):
        """Export audit log to JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump([asdict(entry) for entry in self.logs], f, indent=2, ensure_ascii=False)
        print(f"Audit log exported to {filepath}")

    def get_summary(self) -> dict:
        """Get summary statistics."""
        total = len(self.logs)
        blocked = sum(1 for e in self.logs if e.blocked)
        safe = sum(1 for e in self.logs if e.safe_query)
        attacks = sum(1 for e in self.logs if e.attack_query)
        avg_latency = sum(e.latency_ms for e in self.logs) / total if total > 0 else 0

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "safe_queries": safe,
            "attack_queries": attacks,
            "block_rate": blocked / total if total > 0 else 0,
            "avg_latency_ms": avg_latency,
            "unique_users": len(self.user_stats),
            "uptime_seconds": time.time() - self.start_time
        }


class MonitoringAlert:
    """Monitoring system that tracks metrics and fires alerts.

    This class monitors the security pipeline and alerts when
    thresholds are exceeded, enabling real-time response to
    attacks or anomalies.
    """

    def __init__(self, audit_plugin: AuditLogPlugin = None):
        self.audit_plugin = audit_plugin
        self.alerts = []
        self.alert_thresholds = {
            "block_rate_warning": 0.3,      # Alert if >30% blocked
            "block_rate_critical": 0.5,      # Critical if >50% blocked
            "attack_rate_warning": 0.2,     # Alert if >20% are attacks
            "latency_warning_ms": 5000,     # Alert if avg >5s
            "user_rate_limit_pct": 0.1,     # Alert if >10% users hit rate limit
        }

    def check_metrics(self) -> list:
        """Check current metrics against thresholds and return any alerts."""
        if not self.audit_plugin:
            return []

        new_alerts = []
        summary = self.audit_plugin.get_summary()

        # Check block rate
        if summary["block_rate"] > self.alert_thresholds["block_rate_critical"]:
            new_alerts.append({
                "level": "CRITICAL",
                "type": "HIGH_BLOCK_RATE",
                "message": f"Block rate is {summary['block_rate']:.1%} - possible attack wave",
                "timestamp": datetime.now().isoformat()
            })
        elif summary["block_rate"] > self.alert_thresholds["block_rate_warning"]:
            new_alerts.append({
                "level": "WARNING",
                "type": "ELEVATED_BLOCK_RATE",
                "message": f"Block rate is {summary['block_rate']:.1%} - monitoring",
                "timestamp": datetime.now().isoformat()
            })

        # Check attack rate
        if summary["total_requests"] > 0:
            attack_rate = summary["attack_queries"] / summary["total_requests"]
            if attack_rate > self.alert_thresholds["attack_rate_warning"]:
                new_alerts.append({
                    "level": "WARNING",
                    "type": "HIGH_ATTACK_RATE",
                    "message": f"Attack rate is {attack_rate:.1%} - possible coordinated attack",
                    "timestamp": datetime.now().isoformat()
                })

        # Check latency
        if summary["avg_latency_ms"] > self.alert_thresholds["latency_warning_ms"]:
            new_alerts.append({
                "level": "WARNING",
                "type": "HIGH_LATENCY",
                "message": f"Average latency is {summary['avg_latency_ms']:.0f}ms",
                "timestamp": datetime.now().isoformat()
            })

        self.alerts.extend(new_alerts)
        return new_alerts

    def print_alerts(self):
        """Print all active alerts."""
        if not self.alerts:
            print("\nNo active alerts")
            return

        print("\n" + "=" * 60)
        print("ACTIVE ALERTS")
        print("=" * 60)
        for alert in self.alerts:
            print(f"  [{alert['level']}] {alert['type']}: {alert['message']}")
            print(f"           Time: {alert['timestamp']}")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    # Quick test
    audit = AuditLogPlugin()
    print("AuditLogPlugin created!")
    summary = audit.get_summary()
    print(f"Summary: {summary}")
