#!/usr/bin/env python3
"""
SIEM Alert Triage Automation - Production Deployment Script
Simple, error-free version for production use.
"""

import json
import joblib
import numpy as np
import sys

class ProductionTriage:
    def __init__(self, model_path='false_positive_model.pkl'):
        """Initialize with trained model"""
        try:
            self.model = joblib.load(model_path)
            self.trusted_ips = ['10.0.', '192.168.', '172.16.']
            print(f"? Model loaded successfully from {model_path}")
        except Exception as e:
            print(f"? Error loading model: {e}")
            self.model = None

    def extract_features(self, alert):
        """Extract features from a single alert"""
        # Check if IP is internal
        is_internal = any(alert.get('source_ip', '').startswith(prefix)
                         for prefix in self.trusted_ips)

        # Simple alert type encoding
        alert_type = alert.get('alert_type', 'unknown')
        alert_type_map = {
            'failed_login': 0, 'port_scan': 1, 'malware_detected': 2,
            'data_exfiltration': 3, 'privilege_escalation': 4,
            'brute_force': 5, 'suspicious_download': 6
        }
        alert_type_encoded = alert_type_map.get(alert_type, -1)

        # Other features
        count = alert.get('count', 1)
        hour = alert.get('hour', 12)  # Default to noon if not specified
        is_off_hours = 1 if (hour < 6 or hour > 18) else 0
        is_admin = 1 if alert.get('user') == 'admin' else 0
        is_unknown = 1 if alert.get('user') == 'unknown' else 0

        # Severity encoding
        severity = alert.get('severity', 'Medium')
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        severity_encoded = severity_map.get(severity, 2)

        return [is_internal, alert_type_encoded, count, is_off_hours,
                is_admin, is_unknown, severity_encoded]

    def triage(self, alert):
        """Triage a single alert"""
        if self.model is None:
            return "ERROR_NO_MODEL", 0.0, "Model not loaded"

        try:
            features = self.extract_features(alert)
            fp_prob = self.model.predict_proba([features])[0][1]

            if fp_prob > 0.7:
                return "AUTO_ARCHIVE", fp_prob, "High confidence false positive"
            elif fp_prob > 0.4:
                return "SCHEDULED_REVIEW", fp_prob, "Possible false positive"
            else:
                return "IMMEDIATE_INVESTIGATION", fp_prob, "Likely true positive"
        except Exception as e:
            return "ERROR", 0.0, f"Processing error: {e}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python triage_alerts.py <alerts_json_file>")
        print("Example: python triage_alerts.py sample_alerts.json")
        sys.exit(1)

    triager = ProductionTriage('false_positive_model.pkl')

    try:
        with open(sys.argv[1], 'r') as f:
            alerts = json.load(f)

        if not isinstance(alerts, list):
            alerts = [alerts]

        print(f"\n?? Processing {len(alerts)} alerts...")
        print("-" * 60)

        for i, alert in enumerate(alerts, 1):
            decision, confidence, reason = triager.triage(alert)
            alert_id = alert.get('id', f'Alert-{i}')
            print(f"{alert_id}: {decision} (confidence: {confidence:.1%})")
            print(f"   Reason: {reason}")
            print("-" * 40)

    except Exception as e:
        print(f"? Error: {e}")

if __name__ == "__main__":
    main()
