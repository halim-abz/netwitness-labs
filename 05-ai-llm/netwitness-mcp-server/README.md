# NetWitness MCP Server 🧠

This is a Python implementation of the **Model Context Protocol (MCP)** for the NetWitness Platform.

It acts as a bridge, allowing MCP-compliant AI clients (such as the **Claude Desktop App**, **Gemini CLI**, **ChatGPT**, or **n8n.io**) to query your NetWitness environment.

## 🚀 Capabilities (Tools)

When connected, the AI assistant gains the following "Tools":

* **`get_netwitness_meta_keys`**: Retrieves the list of available NetWitness meta keys and their descriptions for use in query_sessions and query_metakey_values.
* **`get_netwitness_query_syntax`**: Retrieves the NetWitness query syntax guide, including operators, clauses (WHERE, SELECT), time ranges, and example queries.
* **`query_metakey_values`**: Queries aggregated values for a specific NetWitness meta key with counts (top-N query). Use where_clause to filter results (e.g., 'service=443' to see IPs only on HTTPS).
* **`query_sessions`**: Queries NetWitness sessions using WHERE clause syntax.
* **`query_alerts`**: Returns a list of alert records including title, severity, and timestamp.

## 📂 Project Structure

```
netwitness-mcp-server/
├── src/
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Docker file recipe
│   └── netwitness_mcp_server.py    # Main FastMCP entry point
└── README.md                       # This file
```
---
## 🛠️ Installation & Setup
This guide provides the steps to build, configure, and run the NetWitness MCP Server Docker image.
This guide assumes that Docker Desktop is already installed.

### 1. Build the Docker Image
Navigate to the server directory and build the Docker image locally.
```
cd netwitness-mcp-server
docker build -t netwitness-mcp-server .
```

### 2. Configure Environment Variables (Secrets)
Set the required credentials and the NetWitness API URL using Docker MCP secrets.
**NOTE:** Change the IP address and Port for your specific NetWitness environment. Common ports: Concentrator (50105), Broker (50103).
```
docker mcp secret set NETWITNESS_API_URL="https://nw_concentrator_ip:50105"
docker mcp secret set NETWITNESS_USERNAME="admin"
docker mcp secret set NETWITNESS_PASSWORD="netwitness"
docker mcp secret set NW_ADMIN_URL="https://nw_admin_server_ip"
docker mcp secret set NW_ADMIN_USERNAME="admin"
docker mcp secret set NW_ADMIN_PASSWORD="netwitness"
```

### 3. Configure Docker Registry
Append the below content to the Docker MCP's **registry.yaml**
  - Windows: `c:\Users\[user]\.docker\mcp\registry.yaml`
  - Linux: `~/.docker/mcp/registry.yaml`

```registry.yaml
registry:
  netwitness:
    ref: ""
```

### 4. Configure Docker MCP Custom Catalog
Append the below content to the Docker's **custom.yaml** file
  - Windows: `c:\Users\[user]\.docker\mcp\catalogs\custom.yaml`
  - Linux: `~/.docker/mcp/catalogs/custom.yaml`

```custom.yaml
version: 2
name: custom
displayName: Custom MCP Servers
registry:
  netwitness:
    description: "Queries metadata and alerts from NetWitness."
    title: "NetWitness"
    type: server
    dateAdded: "2025-09-20T00:00:00Z"
    image: netwitness-mcp-server:latest
    ref: ""
    readme: ""
    toolsUrl: ""
    source: ""
    upstream: ""
    icon: ""
    tools:
      - name: query_sessions
      - name: query_metakey_values
      - name: query_alerts
      - name: get_netwitness_meta_keys
      - name: get_netwitness_query_syntax

    secrets:
      - name: NETWITNESS_API_URL
        env: NETWITNESS_API_URL
        example: "https://192.168.1.200:50105"
      - name: NETWITNESS_USERNAME
        env: NETWITNESS_USERNAME
        example: "admin"
      - name: NETWITNESS_PASSWORD
        env: NETWITNESS_PASSWORD
        example: "netwitness"
      - name: NW_ADMIN_URL
        env: NW_ADMIN_URL
        example: "https://192.168.1.100"
      - name: NW_ADMIN_USERNAME
        env: NW_ADMIN_USERNAME
        example: "admin"
      - name: NW_ADMIN_PASSWORD
        env: NW_ADMIN_PASSWORD
        example: "netwitness"
    metadata:
      category: security
      tags:
        - network-forensics
        - netwitness
        - security-analytics
      license: MIT
      owner: local
```

### 5. Make the MCP Server Accessible Remotely (Optional)
This is required if the application that needs to access the MCP server is not on the same host.
To make the MCP Server accessible remotely, you must run an MCP Gateway.
Rune the bellow command to make it accessible over _http://mcp_server_ip:8811/mcp_

```
  docker run -d \
    --restart=unless-stopped \
    --name mcp-gateway \
    -p 8811:8811 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $HOME/.docker/mcp:/mcp:ro \
    docker/mcp-gateway \
    --catalog=/mcp/catalogs/docker-mcp.yaml \
    --catalog=/mcp/catalogs/custom.yaml \
    --config=/mcp/config.yaml \
    --registry=/mcp/registry.yaml \
    --secrets=docker-desktop \
    --watch=true \
    --transport=streaming \
    --port=8811
```

---

## 🛠️ Setup Client Applications
This section outlines sample required configurations for related applications like Claude Desktop and Gemini CLI to use the MCP server.

### A. Configure Claude Desktop (Local)
To connect the Claude application to the running MCP Server when both are running on the same host.

1. Copy Config File:
On the system running Claude Desktop, add the below to the **claude_desktop_config.json** file under `%APPDATA%\Claude\claude_desktop_config.json`
Make sure to replace the placeholder **_[YOUR_HOME]_** directory with the appropriate path for your OS. For example:
  - Windows: `C:\\Users\\your_username/.docker/mcp:/mcp",`
  - Linux: `/home/your_username/.docker/mcp:/mcp",`
  - Mac: `/Users/your_username/.docker/mcp:/mcp",`

```claude_desktop_config.json
{
  "mcpServers": {
    "netwitness": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "[YOUR_HOME]/.docker/mcp:/mcp",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

### B. Configure Claude Desktop (Remote)
To connect the Claude application to the running MCP Server when both are running on separate hosts.

1. Install **Node.js**:
Node.js is a prerequisite for using _mcp-remote_. If not installed on the system running Claude Desktop, download and install it: `https://nodejs.org/en/download`

2. Configure Claude Desktop for Remote Access:
Use the following JSON structure for your **claude_desktop_config.json** file, adjusting the IP address as needed to point to your remote MCP Server. See A.1 above for the location of the json file.

```claude_desktop_config.json
{
  "mcpServers": {
    "netwitness": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://mcp_server_ip:8811/mcp",
        "--allow-http"
      ]
    }
  }
}
```

### C. Configure Gemini CLI
Similar to the Claude configuration, but copy the content of the JSON configuration file into the Gemini CLI settings JSON file: `[Home]\.gemini\settings.json`

### D. Configure n8n.io
To use the MCP Server within an n8n automation/AI Agent/AI Workflow.

- Add an **AI Agent**
- Add a **Tool** to the AI Agent
- Chose **MCP Client Tool**
- Endpoint: **http://mcp_server_ip:8811**
- Server Transport: **HTTP Streamable**
- Authentication: **None**

### E. Reload Config
For configuration changes to take effect, completely close and then re-open the application (Claude Desktop or Gemini CLI).

---

## 🛡️ Security & Privacy Guidelines

**CRITICAL WARNING:**
When using these assistants, you are sending data to a public Large Language Model (Anthropic, Google or OpenAI). Data queried from and retruned by your NetWitness instance can be sent to these providers for processing. This data may contain sensitive information. When possible rely on local LLMs (such as Ollama).

2.  **NO PII:** Do not paste Personally Identifiable Information (Usernames, Real Names, Phones) into the chat.
3.  **NO Secrets:** Do not paste internal IP maps, passwords, or API keys.
4.  **Sanitization:** Before asking the AI to analyze a log, replace the real IP `203.0.113.5` with `X.X.X.X` or a generic placeholder.
 
*Note: If you are using an Enterprise version of ChatGPT/Gemini, refer to your corporate policy regarding data retention.*
