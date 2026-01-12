# AI & LLM Integrations 🤖

This directory houses experimental integrations between NetWitness and Generative AI platforms (OpenAI, Google Gemini, Anthropic, etc.).

## 📂 Contents

| Project | Type | Description |
| :--- | :--- | :--- |
| **[`netwitness-mcp-server/`](netwitness-mcp-server/)** | **Code** | A Model Context Protocol (MCP) server to allow LLMs (like Claude Desktop) to query NetWitness directly. |
| **[`custom-assistants/`](custom-assistants/)** | **Config** | Prompts, System Instructions, and Knowledge files for Custom GPTs and Gemini Gems. |

## 🛡️ Security & Privacy Warning

1.  **Data Privacy:** Be extremely cautious about sending PII to public LLM APIs.
2.  **Credentials:** Never hardcode your NetWitness Admin credentials into these tools. Use environment variables.
3.  **Accuracy:** LLMs can hallucinate. Always verify generated queries or syntax against official documentation.
