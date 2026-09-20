# Native model-free one-shot adapter

The JSON runtime accepts an explicit `celln.json-direct/v1` configuration containing exactly one `tool` and a JSON `arguments` string. This is separate from the model-loop configuration: model, URL, history, credentials and additional tools are rejected as unknown fields. It is not a fallback after a model failure.

Input schema identity and argument byte limits are checked before execution. The guest invokes the exact selected executable once, with bounded input/output pipes and a timeout, then validates the returned output against its pinned schema. The adapter has no model broker callback. Executable hash and read-only-file checks are diagnostics, not substitutes for host publisher, closure, execution-grant or namespace admission checks.

This adapter alone does not enforce per-tool aggregate memory authority. Scoped host admission must select an enclosing VM ceiling satisfying the declared tool limits, implement an appropriate stronger bound, or refuse. It must also verify the selected tool and schemas against the admitted immutable catalogue bindings. A caller-supplied configuration is not authority.

## Evidence

`json_direct_adapter_on_real_kvm` uses the rebuilt, signed native JSON fixture package. It launches two distinct cells, checks confirmed runtime execution grants, validates the actual uppercase tool result, and observes zero broker requests. No standing model grant is created. The strict `make conformance-kvm` target includes this case and rejects skipped or missing cases.

This proves native adapter execution, not scoped HTTP admission, a controller-created run, tenant isolation, or installed acceptance. The controller/receiver integration and genuine enduring lifecycle remain required before presenting a deployed manual walkthrough.
