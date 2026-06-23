"""
Honeypot Lab - Local Backend Server
-------------------------------------
Runs on YOUR machine. Uses your existing AWS CLI credentials (~/.aws/credentials)
to query CloudWatch Logs Insights directly, enrich results with GeoIP, and serve
them as JSON to the dashboard. No credentials ever touch the browser.

Setup:
    pip install boto3 flask flask-cors requests

Run:
    python3 server.py

Then open the dashboard HTML in your browser - it will call this automatically.
Leave this terminal window running while you use the dashboard.
"""

import time
import boto3
from flask import Flask, jsonify
from flask_cors import CORS
import requests

# ---- CONFIG: adjust if needed ----
AWS_REGION = ""          # your honeypot's region
LOG_GROUP = "" # your Log Group
QUERY_LOOKBACK_SECONDS = 60 * 60 * 48   # how far back to search (48h default)
GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp"
# -----------------------------------

app = Flask(__name__)
CORS(app)  # allows the dashboard HTML (opened as a local file) to call this server

logs_client = boto3.client("logs", region_name=AWS_REGION)

# Simple in-memory cache so we don't hammer the GeoIP API on every refresh
_geoip_cache = {}


def run_insights_query(query: str, lookback_seconds: int = QUERY_LOOKBACK_SECONDS):
    """Run a CloudWatch Logs Insights query and return parsed result rows."""
    end_time = int(time.time())
    start_time = end_time - lookback_seconds

    start_response = logs_client.start_query(
        logGroupName=LOG_GROUP,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
    )
    query_id = start_response["queryId"]

    # Poll until the query finishes
    while True:
        result = logs_client.get_query_results(queryId=query_id)
        status = result["status"]
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(0.5)

    if status != "Complete":
        raise RuntimeError(f"Insights query did not complete: status={status}")

    rows = []
    for result_row in result["results"]:
        row = {field["field"]: field["value"] for field in result_row}
        rows.append(row)
    return rows


def geoip_lookup(ip: str) -> dict:
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    geo = {"Country": None, "CountryCode": None, "City": None, "Lat": None, "Lon": None, "ISP": None}
    try:
        resp = requests.get(GEOIP_API.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            geo = {
                "Country": data.get("country"),
                "CountryCode": data.get("countryCode"),
                "City": data.get("city"),
                "Lat": data.get("lat"),
                "Lon": data.get("lon"),
                "ISP": data.get("isp"),
            }
    except Exception as e:
        print(f"GeoIP lookup failed for {ip}: {e}")

    _geoip_cache[ip] = geo
    time.sleep(0.3)  # be gentle with the free API
    return geo


LEADERBOARD_QUERY = """
fields @timestamp, @message
| filter @message like /EventID>4625/
| parse @message /<Data Name='IpAddress'>(?<SourceIP>[\\d\\.]+)<\\/Data>/
| filter SourceIP not like /-/ and SourceIP not like /^$/
| stats count(*) as AttackCount by SourceIP
| sort AttackCount desc
"""

USERNAME_QUERY = """
fields @timestamp, @message
| filter @message like /EventID>4625/
| parse @message /<Data Name='TargetUserName'>(?<AccountName>[^<]+)<\\/Data>/
| filter AccountName not like /-/ and AccountName not like /^\\$/
| stats count(*) as Attempts by AccountName
| sort Attempts desc
"""


@app.route("/api/attacks")
def get_attacks():
    """Returns GeoIP-enriched attacker leaderboard as JSON."""
    try:
        rows = run_insights_query(LEADERBOARD_QUERY)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    enriched = []
    for row in rows:
        ip = row.get("SourceIP", "")
        geo = geoip_lookup(ip)
        enriched.append({
            "SourceIP": ip,
            "AttackCount": int(row.get("AttackCount", 0)),
            **geo,
        })

    return jsonify(enriched)


@app.route("/api/usernames")
def get_usernames():
    """Returns username-frequency breakdown as JSON."""
    try:
        rows = run_insights_query(USERNAME_QUERY)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    result = [
        {"AccountName": row.get("AccountName", ""), "Attempts": int(row.get("Attempts", 0))}
        for row in rows
    ]
    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "region": AWS_REGION, "log_group": LOG_GROUP})


if __name__ == "__main__":
    print(f"Honeypot backend starting...")
    print(f"Region: {AWS_REGION}")
    print(f"Log group: {LOG_GROUP}")
    print(f"Open the dashboard HTML in your browser - it will call http://localhost:5000 automatically.")
    app.run(host="127.0.0.1", port=5000, debug=False)
