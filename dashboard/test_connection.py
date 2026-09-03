import os

from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()

client = OpenSearch(
    hosts=[{"host": os.environ.get("OS_HOST", "localhost"),
            "port": int(os.environ.get("OS_PORT", "9200"))}],
    http_auth=(os.environ.get("OS_USER", "admin"), os.environ.get("OS_PASS", "")),
    use_ssl=True,
    verify_certs=False,        # self-signed cert from your cert generator
    ssl_show_warn=False,
)

print("Cluster info:", client.info()["cluster_name"])

# what indices exist?
print("\nWazuh indices:")
for idx in sorted(client.indices.get_alias(index="wazuh-*").keys()):
    print("  ", idx)

# count alerts
res = client.count(index="wazuh-alerts-4.x-*")
print(f"\nTotal alerts indexed: {res['count']}")

# pull one, to see the shape
hit = client.search(index="wazuh-alerts-4.x-*", size=1)["hits"]["hits"][0]["_source"]
print("\nSample alert fields:", list(hit.keys()))
print("Rule:", hit.get("rule", {}).get("id"), "-", hit.get("rule", {}).get("description"))
