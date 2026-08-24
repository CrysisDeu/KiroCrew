# Design — Human-in-the-Loop Tool-Approval Layer

## Overview

The approval layer is the seam between an autonomous agent and any consequential action.
It already exists in Kiro Crew as three cooperating pieces:

1. **Enforcement (backend):** `HookManager.on_tool_call` in `src/kiro_crew/hooks.py`
   returns `TOOL_ALLOW` / `TOOL_AUTO_APPROVE` / `TOOL_DENY` at the PreToolUse boundary,
   applying sensitive-path, exfiltration, write-protected-config, deny-by-default-shell,
   and governance (ceiling ∩ profile) rules. This is the **only** policy authority.
2. **Render (frontend):** `components/ApprovalCard.tsx` + `components/ToolInputPreview.tsx`
   render a pending call as a card, currently as a raw `<pre>` args dump.
3. **Resume (frontend → backend):** `components/ChatInput.tsx` submits the decision via
   the id-scoped `api.resolveApproval(request_id, action)` for plain approve/reject
   (`api.approveChatSlot(slot, …)` is reserved for trust grants); the paused turn resumes
   with the tool either executed or rejected.

This design does NOT add a second policy. It (a) enriches the **render** step with a typed
preview and a batch affordance, (b) documents the **resume** step against the AI-SDK
interruption seam so the pattern is portable, and (c) leaves enforcement exactly where it
is. The App Builder Kit's `kit/tool-views` module supplies the typed preview components;
this spec is the approval-loop contract that consumes them.

## Architecture

```
Agent turn
   │  emits tool call (PreToolUse event)
   ▼
┌──────────────────────────────────────────────┐
│ HookManager.on_tool_call  (hooks.py) — AUTHORITY│
│   TOOL_DENY ──────────► blocked + SEL audit     │  (never surfaced)
│   TOOL_AUTO_APPROVE ──► executes, no prompt      │
│   TOOL_ALLOW ─────────► held as pending decision │
└──────────────────────────────────────────────┘
   │  pending decision (title, purpose, input, tool-call id, slot)
   ▼
┌──────────────────────────────────────────────┐
│ ApprovalCard.tsx  (render via generative UI)    │
│   ToolPreviewFrame (kit/tool-views)             │
│     schema match  → rich typed preview          │
│     no match      → ToolInputPreview <pre>      │
│   [show raw input] always one interaction away  │
│   batch: N pending → one multi-select action    │
└──────────────────────────────────────────────┘
   │  operator clicks approve / reject (+ optional pattern)
   ▼
┌──────────────────────────────────────────────┐
│ onApprove(decision, pattern?) → ChatInput.tsx   │
│   api.resolveApproval(request_id, action)       │  (EXISTING id-scoped path)
└──────────────────────────────────────────────┘
   │  resume the SAME interrupted invocation (by request_id)
   ▼
Tool executes (approved) or is skipped (rejected); agent turn continues
```

### Boundary with existing code (verified paths)

| Existing | Layer relationship |
|---|---|
| `src/kiro_crew/hooks.py` (`on_tool_call`) | **Unchanged.** Sole policy authority; the layer reads its verdict. |
| `website/src/components/ApprovalCard.tsx` | Hosts `ToolPreviewFrame` + the batch affordance. |
| `website/src/components/ToolInputPreview.tsx` | The fallback preview and the "show raw input" surface. |
| `website/src/components/ChatInput.tsx` (`resolveApproval`) | **Unchanged** resume path the layer reuses (id-scoped by `request_id`; `approveChatSlot` is trust-grants only). |
| `website/src/hooks/useWebSocket.ts` | Delivers the pending-decision + resume events (existing). |
| `website/src/kit/tool-views/` (App Builder Kit) | Supplies `ToolPreviewFrame` / schema-matched typed previews. |
| `website/src/types/index.ts` (`tool_input: string`) | The opaque input string a preview parses; no new wire field. |

## Components and Interfaces

### Pending-decision model (frontend, mirrors AI-SDK `UIToolInvocation`)

```ts
// state model only — NOT a transport claim; input-streaming is omitted
// (unreachable on this transport: the pending event arrives input-complete)
type ToolInvocationState =
  | { state: 'input-available';  input: unknown }               // ← the approvable moment
  | { state: 'output-available'; input: unknown; output: unknown }
  | { state: 'output-error';     input: unknown; error: string }

interface PendingDecision {
  slot: string
  approval: PendingApproval    // the verbatim wire event (types/index.ts): carries
                               // request_id (the resume id), tool, tool_input, tool_kind
  toolCallId?: string          // optional; display/correlation only — resume uses
                               // approval.request_id, not this
  invocation: ToolInvocationState  // at 'input-available'
}
```

The approvable moment is `state: 'input-available'`: the input is complete but the tool
has not run. The card renders from this state; resume moves it to `output-available` /
`output-error`.

### Render: `ApprovalCard` + `ToolPreviewFrame`

`ApprovalCard` receives one or more `PendingDecision`s. For each, it delegates the input
body to `ToolPreviewFrame` (from `kit/tool-views`):

- **Schema match** → typed rich preview (e.g. a diff, a table, a chart of the args).
- **No match** → the existing `ToolInputPreview` `<pre>` (Req 2.3, non-regression).
- **Always** → a collapsed "show raw input" control revealing the verbatim
  `approval.tool_input`
  (Req 2.4). The rich preview is lossy by design; the raw string is the ground truth the
  operator can inspect before approving.

Controls (approve / reject / optional pattern field) are keyboard operable with ARIA
roles (Req 2.5).

### Resume: `onApprove` → `resolveApproval`

The decision is passed straight to the existing callback:

```ts
onApprove(decision: 'approve' | 'reject', pattern?: string)
// plain approve/reject → api.resolveApproval(approval.request_id, decision)  (ChatInput.tsx)
// (trust grants only → approveChatSlot; unattended sources downgrade to resolveApproval)
```

`approval.request_id` pins the resume to the interrupted invocation (Req 3.4). The optional
`pattern` (e.g. an "always allow this shape" rule) is forwarded verbatim on the path that
accepts it (Req 3.5); it is a hint to the *next* `on_tool_call` evaluation, never a frontend
policy. The layer introduces no new approval API path (Req 3.3).

### Batch approval

Batch is a **UI affordance over the per-call resume**, not a new transport (Req 4.2).
When N calls are pending in a slot, `ApprovalCard` renders a multi-select; submitting a
batch iterates `resolveApproval(request_id, action)` per included call. A call the gate would deny is visibly
excluded and never included in the batch set (Req 4.3–4.4) — the frontend cannot approve
what the backend denies.

## Portable AI-SDK mapping (Requirement 5)

The portable shape is three steps; the table names what an adopter substitutes.

| Step | Portable shape | Kiro Crew binding | AI-SDK binding |
|---|---|---|---|
| Intercept | evaluate the call before it executes | `HookManager.on_tool_call` | a tool with no `execute`, or `prepareStep`/`onStepFinish` interruption |
| Render | build a card from the invocation state | `ApprovalCard` + `ToolPreviewFrame` | render from `UIToolInvocation` at `input-available` |
| Resume | apply the decision to the same invocation | `resolveApproval(request_id, action)` | `addToolResult({ toolCallId, output })` + continued stream |

**Explicit boundary (Req 5.3):** the *enforcement* (`on_tool_call`) and the *transport*
(`resolveApproval` / `approveChatSlot`) are Kiro-Crew-specific — an adopter swaps in their own. The *portable*
part is: intercept before execute, render a card from the invocation state, resume the
same invocation on decision. **The AI-SDK `UIToolInvocation` union is reused as a state
model, not a transport claim (Req 5.4)** — Kiro Crew's chat transport is markdown +
`<mcwidget>` opaque strings (`useBlockAssembler.ts`, `types/index.ts`), not a typed
`tool-<name>` part stream, exactly as documented for the App Builder Kit tool-view encoding.

## Data Models

The layer adds **no new backend wire field.** A `PendingDecision` is assembled on the
frontend from the existing PreToolUse event (title, `tool_input` string) already delivered
over `useWebSocket.ts`. The typed preview parses `approval.tool_input` against a `kit/tool-views`
schema; a parse failure downgrades to `<pre>` (no throw).

## Error Handling

- A schema parse failure on the preview downgrades to `ToolInputPreview` `<pre>` and logs
  via the existing logger — it never blocks the operator from deciding.
- A resume that references a stale/closed `toolCallId` is a no-op with a surfaced notice,
  never a re-issued call (Req 3.4).
- A batch that includes a now-denied call excludes it and reports the exclusion; the
  remaining approvals proceed.
- Enforcement errors (governance deny, sensitive-path) are owned by `on_tool_call` and its
  SEL audit — the layer surfaces the deny, it does not handle or suppress it.

## Testing Strategy

- **Unit (vitest):** `ApprovalCard` renders each `PendingDecision` state; schema-match vs
  `<pre>` fallback; "show raw input" reveals verbatim `approval.tool_input`; keyboard/ARIA on controls.
- **Resume:** approve and reject each route through a mocked `onApprove`/`resolveApproval`
  with the correct `request_id`/`pattern`; a stale `request_id` is a no-op.
- **Batch:** multi-select resolves per-call; a denied call is excluded, not approved.
- **Enforcement non-bypass:** a `TOOL_DENY` verdict never yields an approvable card and
  no operator affordance executes it (Req 6.1–6.2).
- **Backend (pytest):** reuse `test/test_dashboard_approval.py`, `test_auto_approve.py`,
  `test_approval_threading.py` patterns to assert the gate verdicts are unchanged and the
  SEL audit still fires.
- **Screenshot Evidence:** capture pending / approved / rejected / raw-expanded states via
  dev-server + Playwright (light path) for the CI gate.

## CI / constraints (repo-specific)

- Screenshot Evidence gate — the four approval states are the required frames.
- jscpd 0% — reuse `ApprovalCard`/`ToolInputPreview`/`ChatInput`; do not fork them.
- catalogParity — all new `i18nT()` keys land in every locale file.
- PR Hygiene — single squashed commit per PR.
