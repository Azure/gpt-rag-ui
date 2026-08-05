---
applyTo: "public/**,.chainlit/**,chainlit.config.yaml,chainlit.md"
---

# Chainlit presentation and accessibility rules

- Keep CSS in `public/custom.css`, theme variables in `public/theme.json`,
  custom elements in `public/elements/`, and Chainlit settings in `.chainlit/`
  or `chainlit.config.yaml`.
- Preserve semantic controls, labels, keyboard operation, visible focus,
  readable contrast, screen-reader status, responsive layout, and
  reduced-motion compatibility.
- Verify both light and dark themes and the affected standalone and embedded
  modes.
- Avoid brittle Chainlit selectors when a stable hook exists. Revalidate
  custom selectors when upgrading Chainlit.
- Do not enable unsafe HTML or weaken CSP, origin, framing, authentication, or
  download protections for presentation needs.
- Keep strings and interaction behavior consistent with existing localization
  and Chainlit conventions.
