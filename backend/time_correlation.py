# backend/time_correlation.py

import ipaddress

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def correlate_flows(findings):
    """
    Perform probabilistic time-based correlation between Tor-like flows.
    This does NOT deanonymize Tor. It correlates flows observed at the same
    capture vantage point using temporal fingerprints and confidence scores.
    """

    entry_flows = []
    exit_flows = []

    # Step 1: classify flows heuristically
    for f in findings:
        origin = f.get("origin_ip")
        exit_ip = f.get("exit_ip")

        if is_private_ip(origin):
            entry_flows.append(f)
        elif is_private_ip(exit_ip) and not is_private_ip(origin):
            exit_flows.append(f)


    correlations = []

    # Step 2: correlate via temporal fingerprints
    for e in entry_flows:
        for x in exit_flows:
            fp_e = e.get("temporal_fingerprint")
            fp_x = x.get("temporal_fingerprint")

            if not fp_e or not fp_x:
                continue

            # simple fingerprint match heuristic
            if fp_e == fp_x:
                temporal_score = 0.9
                match = True
            else:
                temporal_score = 0.3
                match = False

            ml_conf = (e.get("confidence", 0) + x.get("confidence", 0)) / 200.0

            final_score = round(
                (0.6 * temporal_score + 0.4 * ml_conf), 3
            )

            correlations.append({
                "entry_origin_ip": e.get("origin_ip"),
                "exit_destination_ip": x.get("exit_ip"),
                "entry_fingerprint": fp_e,
                "exit_fingerprint": fp_x,
                "temporal_match": match,
                "correlation_confidence": final_score
            })

    return correlations
