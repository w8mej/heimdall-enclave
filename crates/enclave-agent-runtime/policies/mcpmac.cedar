// MCPMac v3.0 baseline policy set (FS-704 §4, ADR-007, ADR-008, ADR-018).
// Default is deny; `forbid` always overrides `permit`.

@id("tool-invoke-baseline")
permit (principal, action == MCPMac::Action::"InvokeTool", resource)
when {
  context.input_c <= resource.sink_clearance &&
  context.ast_taint < 3 &&
  context.target_namespace == resource.namespace
};

@id("biba-no-t3-in-ast-slots")
forbid (principal, action, resource)
when { context has ast_taint && context.ast_taint >= 3 };

@id("delegation-depth")
forbid (principal, action, resource)
when { principal.depth > 4 };

@id("a3-a4-require-hardware-intent")
forbid (principal, action == MCPMac::Action::"InvokeTool", resource)
when { resource.action_class >= 3 && !context.hw_grant };

@id("bulk-confidential-requires-a4")
forbid (principal, action == MCPMac::Action::"InvokeTool", resource)
when { context.row_count > 1 && context.input_c >= 3 && resource.action_class < 4 };

@id("root-mutation-requires-signed-root-taint")
forbid (principal, action == MCPMac::Action::"InvokeTool", resource)
when { resource.mutates_root && (context.input_t > 0 || !context.hw_grant) };

@id("declassify-enum-bounded")
permit (principal, action == MCPMac::Action::"DeclassifyEnum", resource)
when { context.qif_mb >= 0 && context.qif_mb <= 12000 && context.ast_taint < 3 };

@id("gui-actuation-sandboxed-targets")
permit (principal, action == MCPMac::Action::"ActuateGui", resource)
when { resource.url_origin != "" && resource.app_bundle_id == "org.mcpmac.cdp-sandbox" };

@id("gui-actuation-protected-surfaces")
forbid (principal, action == MCPMac::Action::"ActuateGui", resource)
when {
  ["com.apple.systempreferences", "com.apple.keychainaccess", "com.apple.Terminal",
   "com.apple.CoreAuthUI", "org.mcpmac.enclaveintent"].contains(resource.app_bundle_id)
};

// Custody::ReversibleTokenize (ADR-007 §3): deny by default. An
// organisation's signed bundle names each approved workflow explicitly, e.g.
//   @id("custody-workflow-fraud-review")
//   permit (principal, action == Custody::Action::"ReversibleTokenize",
//           resource == Custody::Workflow::"fraud-review")
//   when { context.profile >= 2 };
// No caller-supplied attribute can grant it (GAP-05).

@id("custody-never-in-l1")
forbid (principal, action == Custody::Action::"ReversibleTokenize", resource)
when { context.profile < 2 };
