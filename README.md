# Year9_10_farm

Standalone Urban Farm applied mathematics site.

## Build

Requires [Quarto](https://quarto.org/).

```bash
quarto render
```

Output is written to the `docs/` folder.

## GitHub Pages

This repo includes a GitHub Actions workflow to publish the site.

1. Go to Settings > Pages.
2. Under Build and deployment, select GitHub Actions.
3. Push to `main` to trigger the publish workflow.

## Security Scanning

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the scanner, pre-commit hook, and protection steps.

## Structure

- `_quarto.yml` - site configuration
- `index.qmd` - home page
- `farm/` - unit content and resources
- `styles.css` - shared styling
