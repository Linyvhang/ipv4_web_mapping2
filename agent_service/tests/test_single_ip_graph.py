from agent_service.services.single_ip_graph import build_single_ip_graph, initial_state


def test_initial_state_defaults_to_saving_latest_scan_result() -> None:
    assert initial_state("192.0.2.1") == {
        "ip": "192.0.2.1",
        "scan_round": None,
        "save_result": True,
    }


def test_initial_state_accepts_explicit_scan_round_and_temporary_mode() -> None:
    state = initial_state("192.0.2.1", scan_round=4, save_result=False)
    assert state["scan_round"] == 4
    assert state["save_result"] is False


def test_graph_compiles_with_analyze_node() -> None:
    graph = build_single_ip_graph(object())
    assert set(graph.get_graph().nodes) == {"__start__", "analyze", "__end__"}
