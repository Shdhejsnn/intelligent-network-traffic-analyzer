from preprocessing.flow_builder import build_flows
from detection.rule_based import detect_port_scan
from detection.statistical import detect_traffic_spike
from storage.database import insert_alert

def main():
    flows = build_flows()

    rule_alerts = detect_port_scan(flows)
    stat_alerts = detect_traffic_spike(flows)

    alerts = rule_alerts + stat_alerts

    if not alerts:
        print("No suspicious behavior detected.")
    else:
        for alert in alerts:
            insert_alert(alert)
            print("ALERT STORED:", alert)

if __name__ == "__main__":
    main()
