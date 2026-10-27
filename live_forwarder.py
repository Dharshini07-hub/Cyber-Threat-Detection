import json
import time
import urllib.request

LOG = "/home/dharsh/cowrie/cowrie/var/log/cowrie/cowrie.json"
URL = "http://10.0.2.2:5000/api/live-event"

print("LIVE FORWARDER STARTED")
print("Monitoring:", LOG)
print("Sending to:", URL)

with open(LOG, "r", encoding="utf-8") as f:
    f.seek(0, 2)

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.5)
            continue

        try:
            event = json.loads(line)

            data = json.dumps(event).encode("utf-8")

            request = urllib.request.Request(
                URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(request, timeout=10) as response:
                print(
                    "[FORWARDED]",
                    event.get("eventid", "unknown"),
                    response.status
                )

        except Exception as error:
            print("[ERROR]", error)