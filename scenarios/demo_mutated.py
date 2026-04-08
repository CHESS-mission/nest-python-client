from nest_client import scenario

from scenarios.demo import init, resume_CPU, stop_CPU, test_CPU


@scenario(
    topology_file="./demo.yaml",
    mutate_topology=True,
    persist_mutated_topology=True,
)
def demo_mutated():
    from nest_client import s, timeline

    with timeline() as t:
        t[0 * s] = (
            init()
            >> test_CPU(0)
            >> stop_CPU("CPU_A")
            >> test_CPU(1, 25 * s)
            >> resume_CPU("CPU_A")
            >> test_CPU(0, 2 * s)
        )
