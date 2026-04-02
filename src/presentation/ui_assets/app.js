const tokenInput = document.getElementById("bearer-token");
const statusText = document.getElementById("status-text");

const savedToken = localStorage.getItem("seal_gateway_token");
if (savedToken) tokenInput.value = savedToken;

document.getElementById("save-token").addEventListener("click", () => {
  localStorage.setItem("seal_gateway_token", tokenInput.value.trim());
  setStatus("Token saved locally");
});

document.getElementById("refresh-all").addEventListener("click", refreshAll);

function authHeaders() {
  const token = tokenInput.value.trim();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${path} -> ${response.status} ${text}`);
  }
  return response.json();
}

function setStatus(text, isError = false) {
  statusText.textContent = text;
  statusText.style.color = isError ? "#b91c1c" : "#166534";
}

function prettySet(elementId, value) {
  document.getElementById(elementId).textContent = JSON.stringify(value, null, 2);
}

function parseJsonOrDefault(raw, fallback) {
  if (!raw.trim()) return fallback;
  return JSON.parse(raw);
}

function buildCredentialPath(type, rawJson) {
  if (!type) return null;
  const data = parseJsonOrDefault(rawJson, {});
  if (type === "StaticRef") return { StaticRef: data };
  if (type === "SystemJit") return { SystemJit: data };
  if (type === "HumanDelegated") return { HumanDelegated: data };
  if (type === "Auto") return { Auto: data };
  throw new Error(`Unsupported credential type: ${type}`);
}

async function refreshAll() {
  try {
    const [specs, workflows, cliTools, securityContexts] = await Promise.all([
      apiGet("/v1/specs"),
      apiGet("/v1/workflows"),
      apiGet("/v1/cli-tools"),
      apiGet("/v1/security-contexts"),
    ]);
    prettySet("spec-list", specs);
    prettySet("workflow-list", workflows);
    prettySet("cli-list", cliTools);
    prettySet("security-context-list", securityContexts);
    document.getElementById("count-specs").textContent = specs.length;
    document.getElementById("count-workflows").textContent = workflows.length;
    document.getElementById("count-cli").textContent = cliTools.length;
    document.getElementById("count-security-contexts").textContent = securityContexts.length;
    setStatus("Dashboard refreshed");
  } catch (error) {
    setStatus(`Refresh failed: ${error.message}`, true);
  }
}

document.getElementById("spec-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const credentialType = document.getElementById("spec-credential-type").value;
    const credentialJson = document.getElementById("spec-credential-json").value;
    const body = {
      name: document.getElementById("spec-name").value.trim(),
      base_url: document.getElementById("spec-base-url").value.trim(),
      source_url: document.getElementById("spec-source-url").value.trim() || null,
      inline_json: parseJsonOrDefault(document.getElementById("spec-inline-json").value, {}),
      source_fetch_url: null,
      credential_path: buildCredentialPath(credentialType, credentialJson),
    };
    await apiPost("/v1/specs", body);
    setStatus("Spec saved");
    await refreshAll();
  } catch (error) {
    setStatus(`Spec error: ${error.message}`, true);
  }
});

document.getElementById("workflow-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const body = {
      name: document.getElementById("wf-name").value.trim(),
      description: document.getElementById("wf-description").value.trim(),
      api_spec_id: document.getElementById("wf-api-spec-id").value.trim(),
      input_schema: parseJsonOrDefault(document.getElementById("wf-input-schema").value, {}),
      steps: parseJsonOrDefault(document.getElementById("wf-steps").value, []),
    };
    await apiPost("/v1/workflows", body);
    setStatus("Workflow saved");
    await refreshAll();
  } catch (error) {
    setStatus(`Workflow error: ${error.message}`, true);
  }
});

document.getElementById("cli-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const credentialType = document.getElementById("cli-credential-type").value;
    const credentialJson = document.getElementById("cli-credential-json").value;
    const subcommands = document.getElementById("cli-subcommands").value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const body = {
      name: document.getElementById("cli-name").value.trim(),
      description: document.getElementById("cli-description").value.trim(),
      docker_image: document.getElementById("cli-image").value.trim(),
      allowed_subcommands: subcommands,
      require_semantic_judge: document.getElementById("cli-semantic").value === "true",
      default_timeout_seconds: Number(document.getElementById("cli-timeout").value),
      registry_credential_path: buildCredentialPath(credentialType, credentialJson),
    };
    await apiPost("/v1/cli-tools", body);
    setStatus("CLI tool saved");
    await refreshAll();
  } catch (error) {
    setStatus(`CLI tool error: ${error.message}`, true);
  }
});

document.getElementById("security-context-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const body = {
      name: document.getElementById("ctx-name").value.trim(),
      allow_workflow_tools: document.getElementById("ctx-workflow").checked,
      allow_cli_tools: document.getElementById("ctx-cli").checked,
      allow_explorer: document.getElementById("ctx-explorer").checked,
      allow_human_delegated_credentials: document.getElementById("ctx-human").checked,
    };
    await apiPost("/v1/security-contexts", body);
    setStatus("Security context saved");
    await refreshAll();
  } catch (error) {
    setStatus(`Security context error: ${error.message}`, true);
  }
});

refreshAll();
