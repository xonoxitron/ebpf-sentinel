# Custom detection rules

## Use the lab config (isolated)

```bash
sudo -E ./target/release/sentinel --config examples/config/custom-rule-lab.yaml
./examples/triggers/custom-rule.sh
```

## Add to bundled rules

Copy a rule into the main rules directory:

```bash
cp examples/rules/demo-tmp-echo.yaml rules/
# restart sentinel with config/sentinel.yaml
```

Rule files must use unique `id` values. See [`rules/`](../rules/) for production-style examples.
