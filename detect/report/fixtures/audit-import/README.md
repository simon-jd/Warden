# Synthetic k8saudit alerts and Stratus receipts

Inputs of `detect/report/test_audit_alert_import.py`, made up for the test:
three runs (`receipt-a.json` and `receipt-b.json` with a `correlation_id`,
`receipt-c.json` without) and nine alerts in the shape the k8saudit
instance's collector keeps them (`alerts.jsonl`, with the fields
`detect/falco/falco-k8saudit.yaml` appends). They are not real alerts and
show nothing about detection. What each alert is for:

1. cluster-scoped, run A's User-Agent: A by correlation ID;
2. `kube-system`, run A's User-Agent: A by correlation ID;
3. Terraform's User-Agent with run A's ID appended: A by correlation ID;
4. `warden-lab`, run B's User-Agent: B by correlation ID and namespace;
5. `warden-lab`, a controller's request in B's window: B by namespace only (the hazard `check-empty` guards against);
6. `warden-lab`, run A's User-Agent inside B's window: no run (A's own request, outside A's window);
7. run C's label in `warden-lab`: C by label and namespace;
8. `kube-system` in C's window, no run key: no run;
9. run B's User-Agent after B's window: no run.
