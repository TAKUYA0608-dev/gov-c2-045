"""GOV-C2-045 — inner domain workflow graph (Cat 2).

Instantiated by DisclosureReviewWorkflowGraphNode.get_subgraph() in graph.py. Linear topology with
per-node skip guards (conditional edges don't propagate across the subgraph boundary):

    START → record_inventory_classify → policy_flag → review_packet_synthesize → human_gate → END

On rejected / 0-record input, record_inventory_classify sets record_count=0 (+error_code); policy_flag
and human_gate no-op and review_packet_synthesize emits the out-of-scope safe answer — no fabricated
redaction candidates.
"""

from __future__ import annotations
from typing import Any

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState

from src.nodes.human_gate_node import HumanGateNode
from src.nodes.policy_flag_node import PolicyFlagNode
from src.nodes.record_inventory_classify_node import RecordInventoryClassifyNode
from src.nodes.review_packet_synthesize_node import ReviewPacketSynthesizeNode
from src.schemas.state import State


class DisclosureReviewWorkflow(BaseGraph):
    """Inner graph: inventory/classify → policy-flag → packet-synthesize → human-gate."""

    @property
    def name(self) -> str:
        return "DisclosureReviewWorkflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        pass

    def register_nodes(self) -> None:
        # No super() — BaseGraph.register_nodes() is abstract.
        self._nodes["record_inventory_classify"] = RecordInventoryClassifyNode()
        self._nodes["policy_flag"] = PolicyFlagNode()
        self._nodes["review_packet_synthesize"] = ReviewPacketSynthesizeNode()
        self._nodes["human_gate"] = HumanGateNode()

    def add_edges(self) -> None:
        # Static linear backbone; the 0-record / rejected skip is handled by per-node guards.
        self._sg.add_edge(START, "record_inventory_classify")
        self._sg.add_edge("record_inventory_classify", "policy_flag")
        self._sg.add_edge("policy_flag", "review_packet_synthesize")
        self._sg.add_edge("review_packet_synthesize", "human_gate")
        self._sg.add_edge("human_gate", END)

    def route(self, state: AgentState) -> str:
        """Required by the BaseGraph ABC. Linear topology → not wired to a conditional edge."""
        if state.get("error_code") or state.get("record_count", 0) == 0:
            return "review_packet_synthesize"
        return "policy_flag"

    def get_output(self, state: AgentState) -> dict[str, Any]:
        return {
            "output": state.get("result"),
            "status": state.get("status"),
            "record_count": state.get("record_count", 0),
            "error_code": state.get("error_code"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
