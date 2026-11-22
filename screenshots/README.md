# Screenshot gallery

Examples of the upload workflow, reports, and Explorer. Click a preview to open the full-size image.

## Diagrams

### Architecture

<a href="../docs/diagrams/vulnscope-architecture.png"><img src="../docs/diagrams/vulnscope-architecture.png" alt="VulnScope architecture diagram" width="800"></a>

Inputs, the Docker image, the analysis chain from parsers to reports, the upload page, the Security Assistant, Compare, the run folder and the optional outbound connections.

### End to end

<a href="../docs/diagrams/vulnscope-end-to-end.png"><img src="../docs/diagrams/vulnscope-end-to-end.png" alt="VulnScope end-to-end workflow diagram" width="800"></a>

Submitting network telemetry and a vulnerability scan, the analysis steps, and the results. The draw.io files are in [docs/diagrams](../docs/diagrams/).

## Explorer and Security Assistant

### Security Assistant drawer

<a href="security_assistant.jpg"><img src="security_assistant.jpg" alt="Explorer focused on web01 with a Security Assistant conversation open" width="800"></a>

The focused host graph sits beside a Security Assistant answer about the findings and observed connections.

### 3D Explorer

<a href="explorer_3d_artex.jpg"><img src="explorer_3d_artex.jpg" alt="3D Explorer of the ARTEX sample with outside addresses on the arc overhead" width="720"></a>

The ARTEX sample in 3D: subnets as platforms, hosts as pillars sized by risk, and the outside addresses that reached in on the INTERNET arc.

### Explorer overview

<a href="explorer_current_overview.jpg"><img src="explorer_current_overview.jpg" alt="Explorer overview of the sample network in 3D" width="720"></a>

The Explorer opens in 3D: each subnet is a platform, hosts are pillars sized by risk, and the top outside addresses sit on the INTERNET arc. The host list on the left is grouped by subnet.

### Focused host

<a href="explorer_current_host.jpg"><img src="explorer_current_host.jpg" alt="Explorer focused on web01 with its host details open" width="720"></a>

Outside addresses appear to the left, connected internal hosts to the right, and the host details in the pane.

## Upload workflow and reports

<a href="upload_current.jpg"><img src="upload_current.jpg" alt="The upload page: report details, options, then a folder to analyze" width="600"></a>

The upload page: optional report details, then Options used by either way of analyzing (internal networks, an IOC CSV, skipping the large copies), a folder to analyze in place, and uploads folded under **Upload files instead**.

<a href="upload_olive_drab.jpg"><img src="upload_olive_drab.jpg" alt="The upload page in the Olive Drab theme" width="600"></a>

Olive Drab uses a subdued map backdrop; SOC Dark and Matrix use signal lines, while Light uses a soft gradient.

<a href="results_current.jpg"><img src="results_current.jpg" alt="Results page with report links and Security Assistant button" width="600"></a>

The results page links to the reports and Explorer and opens Security Assistant in a right-side drawer.

<a href="results_assistant_drawer.jpg"><img src="results_assistant_drawer.jpg" alt="Results page with the Security Assistant drawer open" width="600"></a>

<a href="executive_dark.png"><img src="executive_dark.png" alt="Dark-themed executive summary report" width="400"></a>

The dark executive summary with key numbers, top risks, an activity diagram, and recommended actions.

<a href="executive_light_detail.png"><img src="executive_light_detail.png" alt="Light-themed executive summary detail" width="400"></a>

A light-theme close-up of the executive report's key numbers, top risks, and activity diagram.

<a href="technical_dark.png"><img src="technical_dark.png" alt="Dark-themed technical analysis report" width="320"></a>

The dark technical report covering data quality, prioritized findings, and per-host evidence.
