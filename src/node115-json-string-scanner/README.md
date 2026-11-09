# Shared strict JSON byte scanner

See [the target-bound contract](../../research/work-items/RE-014-node115-json-string-scanner/README.md).
`scan` consumes content after an already-consumed opening quote and returns a
borrowed input/scratch slice or a raw error-code boundary with cursor and scratch
preserved. It deliberately returns bytes without claiming raw-input UTF-8 validity.
