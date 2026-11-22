# Security Assistant

The Security Assistant is linked from every results page and the Explorer.

Out of the box the Security Assistant is **Built-in (offline, no AI)**: it answers questions and
writes a brief from the run's own results with fixed rules and templates, and sends nothing
anywhere. Ask about a host, CVE, plugin, outside IP or IOC, or about priorities, callbacks, lateral
movement and coverage gaps; answers include ready-to-paste Zeek and Palo Alto filters.

To use a model instead, open **Security Assistant settings** and pick a provider:

| Provider | What it is | Key |
| --- | --- | --- |
| `offline` (default) | Built-in rules and templates, no AI model, nothing sent | none |
| `anthropic` | Claude via the Anthropic SDK (`pip install anthropic`) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI's API or an OpenAI-hosted gateway | `OPENAI_API_KEY` |
| `local` | Any OpenAI-compatible server you run (Ollama, vLLM, LM Studio, llama.cpp) | usually none |

With a hosted provider, correlated results (not raw logs) leave your network; **Redact IPs and
hostnames** replaces them with tokens and refuses to send if any survive. If the endpoint is
neither OpenAI's API nor this computer, the settings page warns that questions, run data and the
key will go to that server. The same features work from the terminal (`brief`, `ask`,
`analyze --llm`); see [Methods](../METHODS.md#security-assistant) for flags and safeguards.

## Article briefs

When IOC matches carry source article links and you have chosen OpenAI,
**Generate article briefs with OpenAI** on the results page summarizes each article. Nothing is
sent until you click it.
