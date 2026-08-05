# Frontend accessibility

- Treat accessibility as functional behavior, not visual polish.
- Preserve semantic controls, labels, heading order, keyboard operation,
  visible focus, logical focus movement, and screen-reader announcements.
- Verify text, controls, status information, links, citations, and disabled
  states have readable contrast in both light and dark themes. Do not rely on
  color alone to communicate meaning.
- Keep layouts usable at narrow widths and browser zoom. Avoid fixed
  positioning that obscures messages, controls, dialogs, or mobile content.
- Respect reduced-motion preferences and avoid animation that blocks input or
  understanding.
- Keep CSS in `public/custom.css`, theme variables in `public/theme.json`, and
  Chainlit presentation settings in `.chainlit/` or `chainlit.config.yaml`.
- Chainlit selectors may change between versions. Prefer stable hooks and
  verify login, chat, history, feedback, upload, citation, error, and embedded
  states after framework upgrades.
- Do not enable unsafe HTML or weaken Content Security Policy, origin, or
  framing protections to achieve a visual result.

For presentation changes, record the themes, viewport sizes, input methods,
and authentication modes that were exercised.
