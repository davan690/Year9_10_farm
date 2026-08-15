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

## Recent Changes

- **Unit reorganisation** — units moved around; headers still need updating (`d3b4657`)
- **Image reorganisation** — images consolidated into the `images/` folder (`ca1841c`)
- **Spring program** — spring program content in progress (`02f5601`)
- **Mapping assessment** — first mapping assessment tightened up (`019b478`)
- **Status screenshot** — current site status screenshot added (`25ad517`)
- **Hazards template** — hazards unit template added (`24bc07b`)

## Structure

- `_quarto.yml` - site configuration
- `index.qmd` - home page
- `units-overview.Rmd` - unit sequence overview
- `missions/` - mission pages
- `resources/` - shared unit resources
- `images/` - all site images
- `hazards/` - hazard posters and health & safety resources
- `styles.css` - shared styling
