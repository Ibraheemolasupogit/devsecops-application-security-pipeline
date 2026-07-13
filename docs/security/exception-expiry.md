# Exception Expiry

Exception expiry is evaluated with `LIFECYCLE_AS_OF_DATE` or the deterministic default in lifecycle policy.

```bash
make lifecycle-expiry
```

```mermaid
flowchart TD
    A["active exception"] --> B{"Expiry date"}
    B -- "within warning window" --> C["expiring_soon"]
    B -- "past as-of date" --> D["expired"]
    D --> E["reactivate or escalate finding"]
    E --> F["assigned"]
```

Expired exceptions are exported to `outputs/security/lifecycle/expired-exceptions.csv`. Expiring exceptions are exported to `outputs/security/lifecycle/expiring-exceptions.csv`.
