/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Unit Tests for Packet Filter, Metal Compute Fence, and Multi-Agent QIF Tree
-/

import Enclave.PacketFilter
import Enclave.MetalFence
import Enclave.MultiAgentQifTree

namespace Enclave.Test

open Enclave

-- Packet Filter Tests
def pkt_valid_envoy : Packet :=
  { iface := "lo0", proto := Protocol.TCP, src_group := 8701, dst_port := 8443 }

def pkt_wifi_leak : Packet :=
  { iface := "en0", proto := Protocol.TCP, src_group := 8701, dst_port := 8443 }

def pkt_unauthorized_raw_depot : Packet :=
  { iface := "lo0", proto := Protocol.TCP, src_group := 8701, dst_port := 8080 }

def pkt_dns_tunnel : Packet :=
  { iface := "lo0", proto := Protocol.UDP, src_group := 8701, dst_port := 53 }

theorem test_pf_envoy_allowed : evalPacketFilter pkt_valid_envoy = Verdict.Pass := by
  rfl

theorem test_pf_wifi_blocked : evalPacketFilter pkt_wifi_leak = Verdict.Drop := by
  rfl

theorem test_pf_raw_depot_blocked : evalPacketFilter pkt_unauthorized_raw_depot = Verdict.Drop := by
  rfl

theorem test_pf_dns_blocked : evalPacketFilter pkt_dns_tunnel = Verdict.Drop := by
  rfl

-- Metal Compute Fence Tests
def cmd_anomalous : CommandBuffer :=
  { cmd_id := 1, surprise_basis_points := 9200, tensor_bytes := 1024 * 1024 }

def cmd_nominal : CommandBuffer :=
  { cmd_id := 2, surprise_basis_points := 3100, tensor_bytes := 1024 * 1024 }

theorem test_metal_anomalous_aborts :
    dispatchCommandBuffer cmd_anomalous = { status := FenceStatus.Aborted, emitted_bytes := 0 } := by
  rfl

theorem test_metal_nominal_passes :
    dispatchCommandBuffer cmd_nominal = { status := FenceStatus.Signaled, emitted_bytes := 1024 * 1024 } := by
  rfl

-- Multi-Agent Tree Test
def sample_tree : AgentTree :=
  AgentTree.Fork [
    AgentTree.Leaf 2500,
    AgentTree.Fork [
      AgentTree.Leaf 1500,
      AgentTree.Leaf 2000
    ]
  ]

theorem test_tree_total_cost : treeTotalMillibits sample_tree = 6000 := by
  rfl

theorem test_tree_within_budget : isTreeWithinBudget sample_tree = true := by
  rfl

end Enclave.Test
