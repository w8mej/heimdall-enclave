//! Real WebKit execution restricted to a built-in owned offline test document.
//!
//! This backend demonstrates actual DOM/input effects without automating a host
//! browser. It deliberately supports no remote navigation, arbitrary JavaScript,
//! cookies, credentials, file URLs, downloads or external pages. It is not the
//! complete production browser/JEPA workflow.
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde_json::Value;

/// Reserved identity for the built-in document; never fetched from the network.
/// This is a development fixture origin, not authorization for an external site.
pub const OWNED_DOCUMENT_ORIGIN: &str = "https://depot-owned.invalid";

/// Real isolated WebKit session; created and used on the process main thread.
#[derive(Debug)]
pub struct OwnedWebKit {
    #[cfg(target_os = "macos")]
    native: *mut std::ffi::c_void,
}

impl OwnedWebKit {
    /// Start a fresh nonpersistent, network-denied WebKit content process.
    pub fn new() -> EnclaveResult<Self> {
        #[cfg(target_os = "macos")]
        {
            let mut status = 0;
            let native = unsafe { enclave_webkit_create(&mut status) };
            if native.is_null() || status != 0 { fail!(EIO, "WEBKIT_START_FAILED", "status={status}"); }
            Ok(Self { native })
        }
        #[cfg(not(target_os = "macos"))]
        { fail!(ENOSYS, "WEBKIT_PLATFORM_UNAVAILABLE"); }
    }

    /// Execute the closed supported CDP subset against actual observed DOM.
    /// Unsupported operations refuse; they never receive fabricated success.
    pub fn dispatch(&mut self, method: &str, params: &Value) -> EnclaveResult<Value> {
        let script = command_script(method, params)?;
        #[cfg(target_os = "macos")]
        {
            let source = std::ffi::CString::new(script).map_err(|_| err!(EINVAL, "WEBKIT_SCRIPT_NUL"))?;
            let mut response = vec![0u8; 65_536];
            let written = unsafe { enclave_webkit_eval(self.native, source.as_ptr(), response.as_mut_ptr(), response.len()) };
            if written <= 0 { fail!(EIO, "WEBKIT_OPERATION_FAILED", "status={written}"); }
            serde_json::from_slice(&response[..written as usize]).map_err(|_| err!(EIO, "WEBKIT_RESULT_INVALID"))
        }
        #[cfg(not(target_os = "macos"))]
        { let _ = script; fail!(ENOSYS, "WEBKIT_PLATFORM_UNAVAILABLE"); }
    }
}

fn command_script(method: &str, params: &Value) -> EnclaveResult<String> {
    let expression = match method {
        "Page.getFrameTree" => "({frameTree:{frame:{id:state.frame,url:location.href,securityOrigin:location.origin}}})".to_owned(),
        "DOM.getDocument" => {
            // The closed subset returns a complete tree or refuses. Silently
            // truncating ancestors/descendants would invalidate WorldGate.
            if params.get("depth").is_some_and(|v| v.as_i64() != Some(-1)) {
                fail!(EINVAL, "WEBKIT_TREE_DEPTH_UNSUPPORTED");
            }
            "(()=>{let count=0,attributeBytes=0;const walk=(e,depth)=>{if(++count>256||depth>32)throw Error('tree-limit');const attributes=[];if(e.attributes){for(const a of e.attributes){attributeBytes+=a.name.length+a.value.length;if(attributeBytes>8192)throw Error('attribute-limit');attributes.push(a.name,a.value);}}const n=nodeId(e);const children=Array.from(e.childNodes,child=>walk(child,depth+1));return {nodeId:n,backendNodeId:n,nodeType:e.nodeType,nodeName:e.nodeName,attributes,childNodeCount:children.length,children};};return {root:walk(document,0)};})()".to_owned()
        }
        "DOM.querySelector" => {
            if params.get("nodeId").is_some_and(|v| v.as_u64() != Some(1)) {
                fail!(EINVAL, "WEBKIT_QUERY_ROOT_INVALID");
            }
            let selector = params.get("selector").and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 512)
                .ok_or_else(|| err!(EINVAL, "WEBKIT_SELECTOR_INVALID"))?;
            let quoted = serde_json::to_string(selector).map_err(|_| err!(EINVAL, "WEBKIT_SELECTOR_INVALID"))?;
            format!("(()=>{{const e=document.querySelector({quoted});return {{nodeId:e?nodeId(e):0}};}})()")
        }
        "DOM.getNodeForLocation" => {
            let x = coordinate(params, "x", 1024.)?;
            let y = coordinate(params, "y", 768.)?;
            format!("(()=>{{const e=document.elementFromPoint({x},{y});if(!e||!e.isConnected)throw Error('target');const n=nodeId(e);return {{nodeId:n,backendNodeId:n,frameId:state.frame}};}})()")
        }
        "DOM.getBoxModel" | "DOM.getOuterHTML" => {
            let node = params.get("nodeId").and_then(Value::as_u64).filter(|n| *n >= 2 && *n <= 4096)
                .ok_or_else(|| err!(EINVAL, "WEBKIT_NODE_INVALID"))?;
            if method == "DOM.getOuterHTML" {
                format!("(()=>{{const e=window.__enclave.nodes.get({node});if(!e||e.nodeType!==1||!e.isConnected)throw Error('stale');return {{outerHTML:e.outerHTML}};}})()")
            } else {
                format!("(()=>{{const e=window.__enclave.nodes.get({node});if(!e||e.nodeType!==1||!e.isConnected)throw Error('stale');const r=e.getBoundingClientRect();return {{model:{{content:[r.left,r.top,r.right,r.top,r.right,r.bottom,r.left,r.bottom],width:r.width,height:r.height}}}};}})()")
            }
        }
        "Input.dispatchMouseEvent" => {
            let kind = params.get("type").and_then(Value::as_str)
                .filter(|k| matches!(*k, "mousePressed" | "mouseReleased"))
                .ok_or_else(|| err!(EINVAL, "WEBKIT_MOUSE_TYPE"))?;
            let x = coordinate(params, "x", 1024.)?;
            let y = coordinate(params, "y", 768.)?;
            if params.get("button").and_then(Value::as_str) != Some("left") { fail!(EINVAL, "WEBKIT_MOUSE_BUTTON"); }
            if kind == "mousePressed" {
                format!("(()=>{{const e=document.elementFromPoint({x},{y});if(!e||!e.isConnected)throw Error('target');window.__enclave.down={{e,x:{x},y:{y}}};return {{}};}})()")
            } else {
                // Resolve, compare and act inside a single JS task. A changed
                // target or pointer position cannot click an earlier element.
                format!("(()=>{{const d=window.__enclave.down;window.__enclave.down=null;const e=document.elementFromPoint({x},{y});if(!d||d.e!==e||!e.isConnected||d.x!=={x}||d.y!=={y})throw Error('changed-target');e.focus();e.click();return {{}};}})()")
            }
        }
        "Input.insertText" => {
            let text = params.get("text").and_then(Value::as_str).filter(|s| s.len() <= 4096)
                .ok_or_else(|| err!(EINVAL, "WEBKIT_TEXT_INVALID"))?;
            let quoted = serde_json::to_string(text).map_err(|_| err!(EINVAL, "WEBKIT_TEXT_INVALID"))?;
            format!("(()=>{{const e=document.activeElement;if(!e||e.tagName!=='INPUT'||e.type!=='text')throw Error('input-target');e.value+={quoted};e.setAttribute('value',e.value);e.dispatchEvent(new InputEvent('input',{{bubbles:true,inputType:'insertText',data:{quoted}}}));return {{}};}})()")
        }
        _ => fail!(ENOSYS, "WEBKIT_METHOD_UNSUPPORTED"),
    };
    // All IDs name real nodes in this exact owned document. Node 1 is the
    // document; IDs are never reused, capped at 4096, and reset per session.
    // The native base URL and this guard must agree on the actual observed URL.
    Ok(format!("(()=>{{if(location.href!=='{OWNED_DOCUMENT_ORIGIN}/')throw Error('origin');const state=window.__enclave;if(!state||state.document!==document)throw Error('document');const nodeId=e=>{{let n=state.ids.get(e);if(!n){{if(state.seq>=4096)throw Error('node-limit');n=++state.seq;state.ids.set(e,n);state.nodes.set(n,e);}}return n;}};return {expression};}})()"))
}

fn coordinate(params: &Value, name: &str, limit: f64) -> EnclaveResult<f64> {
    params.get(name).and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v >= 0. && *v < limit)
        .ok_or_else(|| err!(EINVAL, "WEBKIT_COORDINATE_INVALID"))
}

#[cfg(target_os = "macos")]
impl Drop for OwnedWebKit {
    fn drop(&mut self) { unsafe { enclave_webkit_destroy(self.native); } }
}
#[cfg(target_os = "macos")]
extern "C" {
    fn enclave_webkit_create(status: *mut i32) -> *mut std::ffi::c_void;
    fn enclave_webkit_eval(browser: *mut std::ffi::c_void, source: *const std::ffi::c_char, out: *mut u8, cap: usize) -> i32;
    fn enclave_webkit_destroy(browser: *mut std::ffi::c_void);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn closed_webkit_commands_refuse_navigation_script_injection_and_bad_input() {
        for method in ["Page.navigate", "Runtime.evaluate", "Network.enable", "Browser.getVersion"] {
            assert!(command_script(method, &json!({})).unwrap_err().is("WEBKIT_METHOD_UNSUPPORTED"));
        }
        for params in [json!({"type":"mouseReleased","x":-1,"y":1,"button":"left"}),
            json!({"type":"mouseReleased","x":1,"y":768,"button":"left"}),
            json!({"type":"mouseMoved","x":1,"y":1,"button":"left"}),
            json!({"type":"mousePressed","x":1,"y":1,"button":"right"})] {
            assert!(command_script("Input.dispatchMouseEvent", &params).is_err());
        }
        let injected = "');fetch('https://untrusted.invalid');//";
        let script = command_script("DOM.querySelector", &json!({"selector":injected})).unwrap();
        assert!(script.contains(&serde_json::to_string(injected).unwrap()));
        assert!(command_script("DOM.getOuterHTML", &json!({"nodeId":0})).is_err());
    }

    #[test]
    fn closed_webkit_observation_commands_refuse_partial_trees_roots_and_outside_hits() {
        for depth in [json!(0), json!(1), json!(32), json!(-2), json!("-1"), Value::Null] {
            assert!(command_script("DOM.getDocument", &json!({"depth":depth}))
                .unwrap_err().is("WEBKIT_TREE_DEPTH_UNSUPPORTED"));
        }
        assert!(command_script("DOM.getDocument", &json!({"depth":-1})).is_ok());
        assert!(command_script("DOM.getDocument", &json!({})).is_ok());
        for root in [json!(0), json!(2), json!(4096), json!("1"), Value::Null] {
            assert!(command_script("DOM.querySelector", &json!({"nodeId":root,"selector":"#increment"}))
                .unwrap_err().is("WEBKIT_QUERY_ROOT_INVALID"));
        }
        assert!(command_script("DOM.querySelector", &json!({"nodeId":1,"selector":"#increment"})).is_ok());
        for point in [json!({"x":-1,"y":0}), json!({"x":1024,"y":0}),
            json!({"x":0,"y":768}), json!({"x":"0","y":1}), json!({"x":0})] {
            assert!(command_script("DOM.getNodeForLocation", &point)
                .unwrap_err().is("WEBKIT_COORDINATE_INVALID"));
        }
        assert!(command_script("DOM.getNodeForLocation", &json!({"x":0,"y":0})).is_ok());
        assert!(command_script("DOM.getNodeForLocation", &json!({"x":1023,"y":767})).is_ok());
    }

    #[cfg(all(target_os = "macos", debug_assertions))]
    #[test]
    fn owned_webkit_directory_owner_preserves_collisions_and_releases_only_owned_directory() {
        extern "C" { fn enclave_webkit_directory_ownership_check() -> i32; }
        // SAFETY: no caller pointers or paths; the native hook touches only its
        // owned fixture and invokes the same helper used by actual startup.
        let result = unsafe { enclave_webkit_directory_ownership_check() };
        assert_eq!(result, 0, "actual native directory ownership regression");
        eprintln!("OWNED_WEBKIT_DIRECTORY_OWNERSHIP=true directory_collision=file_and_symlink_preserved owned_mode=0700 owned_cleanup=true");
    }
}
