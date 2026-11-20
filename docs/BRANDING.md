# Branding and themes

## Branding

**Branding** (linked from the upload page) replaces the name before "VulnScope" and adds a small
PNG, JPEG, GIF or WebP logo (up to 512 KB) at Small or Medium size, used by the upload page,
command line, reports and Explorer. Changing it needs a password. Set your own before first use:
run `python3 -m vulnflow branding-password`, then start the server with the
`VULNSCOPE_BRANDING_PASSWORD_HASH` it prints. Branding is saved per user in
`~/.vulnscope/branding.json` (or `$VULNSCOPE_HOME`; in Docker, inside the runs folder).

## Themes

The pages share a theme picker: Graphite (the default), SOC Dark, Amphibious, Olive Drab, Matrix,
High Contrast and Light. The browser remembers the choice, and the Explorer follows it.
Comparisons and reopened reports open in Graphite.
