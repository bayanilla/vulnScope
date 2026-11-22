# Explorer

`explorer.html` is written with every run: a single offline file that opens in Chrome or Edge 80+,
Firefox 113+ or Safari 16.4+. The upload page links it from each results page; you can also open
the file directly.

## Views

The view switcher offers:

- **3D** (the default where WebGL works). Each subnet is a platform and each host a pillar whose
  height is its risk score. Risky paths and the most significant outside addresses, on an arc
  overhead, are drawn. Drag to rotate, right-drag or Shift-drag to pan, middle-drag to move the
  picture up or down, scroll to zoom.
- **Flat** (the 2 key; `explorer.html?2d` always opens flat).
- **Attack paths**, the most likely ways in drawn like a transit map (internet origin, entry, first
  and second pivot). **Simulate fix** shows how much path risk fixing or isolating one host would
  remove; nothing on the network changes.
- **Timeline** (the I key, or `explorer.html#timeline`), a tunnel through time where every flow is a
  chord at the moment it happened, with alerts as rings and IOC lookups as dots.

## Hosts and peers

Click a host, or pick it from the host list (grouped by subnet, riskiest first), and the camera
flies to it. The left side shows outside addresses that exchanged traffic with it; the right side
shows internal peers with an estimated likelihood that a compromise could spread there. The panel
lists every recorded IP with session counts and connection tuples. **Focus** pivots to a peer; Esc
or **← All hosts** goes back. The **?** button explains the current view. Deep links work:
`explorer.html#host=10.0.1.10`.

## Large runs

On busy networks each host keeps its top 200 outside addresses and internal peers in the page;
counts use the full lists, and the upload page loads a host's full lists when you click it. Very
large reports may need Firefox or Safari; see [Configured limits](LIMITS.md).

Drawing limits keep large runs responsive; [Methods](../METHODS.md#explorer-drawing-and-sampling)
explains what is drawn and how the likelihood is estimated.
