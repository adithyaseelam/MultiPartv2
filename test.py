from elasticsearch import Elasticsearch
from ping3 import ping
import time

# Create elastic client (update your endpoint & auth)
es = Elasticsearch(["http://localhost:9200"])

def get_cluster_events():
    # Step 1: Get documents from elastic_agent.status dataset
    query = {
        "size": 1000,
        "_source": ["host.hostname", "kubernetes.event.reason"],
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.type": "kubernetes_cluster"}}
                ]
            }
        }
    }

    res = es.search(index="elastic_agent.status*", body=query)
    events = []
    for hit in res['hits']['hits']:
        hostname = hit['_source'].get('host', {}).get('hostname')
        reason = hit['_source'].get('kubernetes', {}).get('event', {}).get('reason')
        events.append((hostname, reason))
    return events

def get_node_hostname(host_hostname):
    # Query kubernetes.node dataset for label
    query = {
        "size": 1,
        "_source": ["kubernetes.labels.kubernetes_io/hostname"],
        "query": {
            "term": {"host.hostname": host_hostname}
        }
    }
    res = es.search(index="kubernetes.node*", body=query)
    hits = res['hits']['hits']
    if hits:
        return hits[0]['_source'].get('kubernetes', {}).get('labels', {}).get('kubernetes_io/hostname')
    return None

def main():
    events = get_cluster_events()
    null_events = [e for e in events if e[1] is None]

    print(f"Total events with null kubernetes.event.reason: {len(null_events)}")
    if len(null_events) > 100:
        print("More than 100 null values found, skipping ping tests.")
        return

    ping_status_map = {}
    for host_hostname, _ in null_events:
        node_hostname = get_node_hostname(host_hostname)
        if node_hostname:
            result = ping(node_hostname, timeout=2)
            ping_status = True if result else False
            ping_status_map[host_hostname] = ping_status
            print(f"Ping {node_hostname}: {'Success' if ping_status else 'Failed'}")
        else:
            print(f"No node hostname found for {host_hostname}")
        time.sleep(0.1)  # avoid flooding with pings

    # Now you have ping_status_map dict to use
    print("Ping status summary:", ping_status_map)

if __name__ == "__main__":
    main()
