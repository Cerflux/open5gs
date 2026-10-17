#!/usr/bin/env python3
"""Insert one Open5GS subscriber. Only the IMSI is supplied; the rest is fixed.

Defaults match the WebUI new-subscriber form and this compose file
(SST 1, DNN/APN internet, 1 Gbps AMBR, sample K/OPc).

    python3 add_subscriber.py 999700000000001

Requires pymongo. On Ubuntu, system pip is blocked, so use a venv:

    python3 -m venv misc/db/python/.venv
    misc/db/python/.venv/bin/pip install pymongo
    misc/db/python/.venv/bin/python misc/db/python/add_subscriber.py 999700000000001

Or install the distro package: sudo apt install python3-pymongo
MongoDB: mongodb://127.0.0.1:27017/open5gs
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Open5GS import Open5GS

MONGO_HOST = "127.0.0.1"
MONGO_PORT = 27017

# Sample keys from the WebUI. Authentication succeeds only if the SIM
# is programmed with the same K and OPc.
K = "465B5CE8 B199B49F AA5F0A2E E238A6BC"
OPC = "E8ED289D EBA952E4 283B54E8 8E6183CA"
AMF = "8000"

# unit: 0=bps, 1=Kbps, 2=Mbps, 3=Gbps, 4=Tbps
ONE_GBPS = {"uplink": {"value": 1, "unit": 3}, "downlink": {"value": 1, "unit": 3}}


def subscriber(imsi):
    return {
        "imsi": imsi,
        "msisdn": [],
        "imeisv": [],
        "mme_host": [],
        "mme_realm": [],
        "purge_flag": [],
        "subscribed_rau_tau_timer": 12,
        "network_access_mode": 0,
        "subscriber_status": 0,
        "operator_determined_barring": 0,
        "access_restriction_data": 32,
        "ambr": ONE_GBPS,
        "slice": [
            {
                "sst": 1,
                "default_indicator": True,
                "session": [
                    {
                        "name": "internet",
                        "type": 3,
                        "pcc_rule": [],
                        "ambr": ONE_GBPS,
                        "qos": {
                            "index": 9,
                            "arp": {
                                "priority_level": 8,
                                "pre_emption_capability": 1,
                                "pre_emption_vulnerability": 1,
                            },
                        },
                    }
                ],
            }
        ],
        "security": {
            "k": K,
            "op": None,
            "opc": OPC,
            "amf": AMF,
        },
        "schema_version": 1,
        "__v": 0,
    }


def main(argv):
    if len(argv) != 2 or not argv[1].isdigit() or not 1 <= len(argv[1]) <= 15:
        print("usage: add_subscriber.py IMSI", file=sys.stderr)
        print("IMSI is 1-15 digits", file=sys.stderr)
        return 1

    imsi = argv[1]
    db = Open5GS(MONGO_HOST, MONGO_PORT)
    if db.GetSubscriber(imsi):
        print(f"{imsi} already exists", file=sys.stderr)
        return 1

    print(db.AddSubscriber(subscriber(imsi)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
