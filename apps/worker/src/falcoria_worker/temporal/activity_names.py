"""Activity name constants: importable by `workflows.py` without its heavy dependencies.

`activities.py` needs httpx/tempfile/subprocess-touching imports, which must stay
out of the workflow-defining module's import graph (Temporal's sandbox re-imports
that module's top-level code). Referencing activities by name, via these plain
string constants, avoids importing `activities.py` from `workflows.py` at all.
"""

NMAP_SCAN_ACTIVITY = "nmap_scan"
UPLOAD_RESULTS_ACTIVITY = "upload_results"
