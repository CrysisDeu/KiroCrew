# Implementation Plan — Human-in-the-Loop Tool-Approval Layer

This plan enriches the render + resume steps of Kiro Crew's existing approval loop and
documents the portable AI-SDK mapping. The backend enforcement gate (`on_tool_call`) is
NOT modified. Depends on the App Builder Kit's `kit/tool-views` module for the typed
preview components.

- [ ] 0. Establish the `PendingDecision` frontend model and confirm the resume seam
  - Define `PendingDecision` (`slot`, `approval: PendingApproval`, optional `toolCallId`,
    `invocation`) and the `ToolInvocationState` union in a shared types module. The model
    WRAPS the existing `PendingApproval` wire type (`types/index.ts`) rather than re-spelling
    its fields, so `tsc` pins it to the real event shape and it carries `request_id`.
    `ToolInvocationState` is non-generic with three reachable phases
    (`input-available` | `output-available` | `output-error`); `input-streaming` is omitted
    as unreachable on this transport. It mirrors AI-SDK `UIToolInvocation` as a state model only.
  - Confirmed (via reading `useWebSocket.ts` + `ChatInput.tsx`) that a `PendingDecision`
    assembles from the existing PreToolUse event with NO new backend wire field, and that the
    resume identifier is `approval.request_id`: plain approve/reject resolves through the
    id-scoped `api.resolveApproval(request_id, action)` (`ChatInput.tsx`), NOT slot-scoped
    `approveChatSlot` (which is used only for trust grants, and downgrades to `resolveApproval`
    for unattended sources).
  - _Requirements: 3.3, 3.4, 5.1, 6.4_
  - In review: PR #5413 (`feat/tal-pending-decision`) — not yet merged to main; this box
    flips to `[x]` when it lands.

- [ ] 1. Rich preview inside `ApprovalCard` (default view, with raw-input fallback)
  - Host `ToolPreviewFrame` (from `kit/tool-views`) inside `ApprovalCard`/`ToolInputPreview`.
  - Render the typed preview when a schema matches the pending input; fall back to the
    existing `<pre>` when none matches.
  - Add an always-present, collapsed "show raw input" control revealing verbatim `approval.tool_input`.
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 2. Keyboard + ARIA on the approval controls
  - Make approve / reject / pattern controls keyboard operable with correct ARIA roles and
    labels (WCAG AA); verify tab order and focus management for batch operation.
  - _Requirements: 2.5_

- [ ] 3. Wire the resume path (approve / reject / pattern)
  - Route the decision through the existing `onApprove(decision, pattern?)`. Plain
    approve/reject resolves via the id-scoped `api.resolveApproval(request_id, action)`
    (`ChatInput.tsx`); the slot-scoped `api.approveChatSlot(slot, …)` is reserved for trust
    grants (and downgrades to `resolveApproval` for unattended sources). Forward an approval
    `pattern` verbatim on the path that accepts it. Do NOT introduce a new approval API path.
  - Ensure resume targets the same invocation via `approval.request_id`; a stale/closed id is
    a no-op with a surfaced notice, never a re-issued call.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 4. Batch approval affordance
  - Render a multi-select when N calls are pending in a slot; submitting a batch iterates
    the per-call `resolveApproval(request_id, action)` resume (no new transport).
  - Visibly exclude any call the gate would deny; never include it in the batch set.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [ ] 5. Enforce the single-authority boundary
  - Assert the frontend never renders an approvable card for a `TOOL_DENY` verdict and
    exposes no affordance that would execute a denied call.
  - Confirm the SEL audit for a deny still fires unchanged (no bypass, no duplication).
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 6. Document the portable AI-SDK mapping
  - Write the intercept → render → resume mapping table naming the Kiro-Crew-specific parts
    (`on_tool_call`, `approveChatSlot`) vs the portable shape, and the AI-SDK resume seam
    (`addToolResult` / continued stream).
  - State explicitly that the `UIToolInvocation` union is a state model, not a transport
    equivalence (Kiro Crew's transport is markdown + `<mcwidget>` opaque strings).
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 7. Tests — render, resume, batch, non-bypass
  - Unit (vitest): each `PendingDecision` state; schema-match vs `<pre>` fallback;
    raw-input reveal; keyboard/ARIA.
  - Resume: approve/reject route through `resolveApproval` with the correct
    `request_id`/`pattern`; a stale `request_id` is a no-op.
  - Batch: per-call resolution; denied call excluded.
  - Non-bypass: a `TOOL_DENY` never yields an approvable card.
  - Backend (pytest): reuse `test_dashboard_approval.py` / `test_auto_approve.py` /
    `test_approval_threading.py` to assert gate verdicts + SEL audit unchanged.
  - _Requirements: 2.*, 3.*, 4.*, 6.*, 7.4_

- [ ] 8. CI compliance + non-regression
  - Capture SHA-pinned screenshots of pending / approved / rejected / raw-expanded states
    for the Screenshot Evidence gate.
  - Land all new `i18nT()` keys in every locale file (catalogParity).
  - Reuse `ApprovalCard`/`ToolInputPreview`/`ChatInput` (jscpd 0%); confirm the
    auto-approve, deny, and single-approve paths show no regression.
  - _Requirements: 7.1, 7.2, 7.3, 7.4_
