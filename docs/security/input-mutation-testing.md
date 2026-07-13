# Input Mutation Testing

`make input-mutation-test` sends malformed and adversarial payloads to the running API.

Covered inputs include empty objects, empty strings, whitespace-only strings, oversized strings, unexpected JSON types, arrays where objects are expected, null payloads, unknown fields, invalid enum values, malformed JSON and wrong content type.

The expected result is controlled 4xx rejection using the stable error schema.
