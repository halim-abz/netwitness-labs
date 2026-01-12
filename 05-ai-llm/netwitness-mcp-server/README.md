# NetWitness MCP Server 🧠

This is a Python implementation of the **Model Context Protocol (MCP)** for the NetWitness Platform.

It acts as a bridge, allowing MCP-compliant AI clients (such as the **Claude Desktop App**, **Gemini CLI**, **ChatGPT**, or **n8n.io**) to query your NetWitness environment.

## 🚀 Capabilities (Tools)

When connected, the AI assistant gains the following "Tools":

* **`get_netwitness_meta_keys`**: Retrieves the list of available NetWitness meta keys and their descriptions for use in query_sessions and query_metakey_values.
* **`get_netwitness_query_syntax`**: Retrieves the NetWitness query syntax guide, including operators, clauses (WHERE, SELECT), time ranges, and example queries.
* **`query_metakey_values`**: Gets aggregated values for a specific NetWitness meta key with counts (top-N query). Use where_clause to filter results (e.g., 'service=443' to see IPs only on HTTPS).
* **`query_sessions`**: Queries NetWitness sessions using SQL-like WHERE clause syntax.
* **`query_alerts`**: Retrieves NetWitness alerts in a specified time range. Returns a list of alert records including title, severity, and timestamp.

## 📂 Project Structure

``` text
netwitness-mcp-server/
├── src/
│   ├── requirements.txt      # Python dependencies
│   ├── Dockerfile
│   └── netwitness_mcp_server.py         # Main FastMCP entry point
├── docker          # Docker config files
│   ├── custom.yaml
│   └── registry.yaml
└── README.md             # This file
