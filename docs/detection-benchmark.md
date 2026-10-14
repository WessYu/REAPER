# Seeded detection benchmark

Run after installing dependencies:

```sh
npm run benchmark:fixtures
```

The benchmark invokes the **real REAPER static engine** against the
repository's existing intentionally vulnerable and secure fixtures. It uses
three planted rule families (`REAPER-SQL-001`, `REAPER-AUTH-001`, and
`REAPER-TENANT-001`) and checks each on both fixture groups.

It reports a six-classification confusion matrix (TP, FP, TN, FN), precision,
recall and specificity, as well as scan duration and the number of findings
outside the labeled rules. The command returns nonzero on any missed planted
rule or any finding from these rule families in the secure fixture.

**Interpretation boundary:** this is six labeled classifications across only
two small synthetic applications. Even a 100% score here does not establish
real-world false-positive or false-negative rates. It is a regression
instrument, not an independent benchmark or an authorization to scan third
party systems.

Commercial acceptance requires a separate evaluation corpus with seeded
vulnerabilities across supported frameworks, multiple secure negative
controls, version-pinned ground truth, analyst-reviewed labels and confidence
intervals. Keep any unknown finding unlabeled rather than silently treating
it as a true positive or false positive.
