#!/usr/bin/env sh
set -eu

ADDRESS="${TEMPORAL_ADDRESS:-temporal:7233}"
NAMESPACE="${TEMPORAL_NAMESPACE:-default}"
RETENTION="${TEMPORAL_RETENTION:-24h}"

echo "Waiting for Temporal server at ${ADDRESS}..."
until tctl --address "${ADDRESS}" cluster health | grep -q SERVING; do
    sleep 2
done
echo "Temporal server is SERVING."

echo "Ensuring namespace '${NAMESPACE}' exists..."
if ! tctl --address "${ADDRESS}" --namespace "${NAMESPACE}" namespace describe >/dev/null 2>&1; then
    echo "Registering namespace '${NAMESPACE}' (retention: ${RETENTION})..."
    tctl --address "${ADDRESS}" --namespace "${NAMESPACE}" namespace register \
        --retention "${RETENTION}" \
        --desc "Namespace for Falcoria (${NAMESPACE})."
else
    echo "Namespace '${NAMESPACE}' already exists."
fi

echo "Waiting for namespace '${NAMESPACE}' to be active in cluster..."
until tctl --address "${ADDRESS}" --namespace "${NAMESPACE}" namespace describe >/dev/null 2>&1; do
    sleep 1
done

echo "Ensuring custom search attributes exist..."
until tctl --address "${ADDRESS}" admin cluster get-search-attributes 2>/dev/null | grep -q "ProjectId"; do
    echo "Registering custom search attributes in cluster..."
    tctl --auto_confirm --address "${ADDRESS}" admin cluster add-search-attributes \
        -n ProjectId -t Keyword \
        -n ScanId -t Keyword \
        -n Mode -t Keyword \
        -n Ip -t Keyword >/dev/null 2>&1 || true
    sleep 2
done

echo "Temporal initialization successfully completed."
