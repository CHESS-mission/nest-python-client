"""
nest_client.seu — SEU (Single Event Upset) fault injection for CHESS FPrime.

Public API
----------
    from nest_client.seu.injector import (
        FaultInjectorClient, InjectionSpec, InjectionResult,
        SEUCampaign, CampaignConfig, PtyOracle, restart_chess_in_qemu,
    )
    from nest_client.seu.elf_analyzer import (
        SymbolInfo, analyze, get_injection_targets, expand_symbol_fields,
    )
    from nest_client.seu.component_layout import SymbolLayout, FieldInfo
"""
