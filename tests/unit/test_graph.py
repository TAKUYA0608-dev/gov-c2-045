# GOV-C2-045 — Unit Tests: Cat 2 graph wiring (outer GraphNode + inner workflow)

import pytest

from src.graph.domain_workflow_graph import DisclosureReviewWorkflow
from src.graph.graph import (
    DisclosureReviewWorkflowGraphNode,
    Graph,
    MunicipalPublicRecordsDisclosureRedactionPacketAgent,
)
from src.schemas.state import State


class TestOuterGraph:
    def test_registry_alias(self):
        assert MunicipalPublicRecordsDisclosureRedactionPacketAgent is Graph

    def test_name_and_state_schema(self):
        g = Graph()
        assert g.name == "MunicipalPublicRecordsDisclosureRedactionPacketAgent"
        assert g.state_schema is State

    def test_main_slot_is_graphnode(self):
        g = Graph()
        g.register_nodes()
        assert isinstance(g._nodes["main"], DisclosureReviewWorkflowGraphNode)
        for slot in ("pre_process", "main", "post_process"):
            assert slot in g._nodes

    def test_error_strategy_propagate(self):
        assert DisclosureReviewWorkflowGraphNode.error_strategy == "propagate"
        assert DisclosureReviewWorkflowGraphNode.propagate_hitl is False

    def test_get_subgraph_is_cached(self):
        node = DisclosureReviewWorkflowGraphNode()
        assert node.get_subgraph() is node.get_subgraph()

    def test_extract_input_prefers_validated(self):
        node = DisclosureReviewWorkflowGraphNode()
        assert node.extract_input({"validated_input": "V", "user_input": "U"}) == "V"
        assert node.extract_input({"user_input": "U"}) == "U"

    def test_merge_output_maps_fields(self):
        node = DisclosureReviewWorkflowGraphNode()
        merged = node.merge_output({}, {"output": '{"x":1}', "record_count": 2, "status": "success",
                                        "error_code": None})
        assert merged["result"] == '{"x":1}' and merged["record_count"] == 2


class _FakeSubgraphBuilder:
    """Minimal stand-in for BaseGraph._sg to exercise add_edges() deterministically."""

    def __init__(self):
        self.edges = []

    def add_edge(self, a, b):
        self.edges.append((a, b))


class TestInnerWorkflow:
    def test_inner_registers_four_nodes(self):
        wf = DisclosureReviewWorkflow(config={})
        wf.register_nodes()
        for slot in ("record_inventory_classify", "policy_flag", "review_packet_synthesize", "human_gate"):
            assert slot in wf._nodes

    def test_route_zero_record_to_synthesize(self):
        wf = DisclosureReviewWorkflow(config={})
        assert wf.route({"record_count": 0}) == "review_packet_synthesize"
        assert wf.route({"record_count": 2}) == "policy_flag"

    def test_add_edges_linear_backbone(self):
        wf = DisclosureReviewWorkflow(config={})
        wf._sg = _FakeSubgraphBuilder()
        wf.add_edges()
        pairs = wf._sg.edges
        assert ("record_inventory_classify", "policy_flag") in pairs
        assert ("policy_flag", "review_packet_synthesize") in pairs
        assert ("review_packet_synthesize", "human_gate") in pairs

    def test_get_output_surfaces_result(self):
        wf = DisclosureReviewWorkflow(config={})
        out = wf.get_output({"result": '{"k":1}', "status": "success", "record_count": 3})
        assert out["output"] == '{"k":1}' and out["record_count"] == 3


class TestServerModule:
    def test_server_imports(self):
        try:
            import src.api.server as server
        except ModuleNotFoundError as exc:
            pytest.skip(f"platform module unavailable in the local stub env: {exc}")
        assert server.app is not None and server.agent is not None
