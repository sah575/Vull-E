from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

BANNER = r"""V   V  U   U  L      L       EEEEE
V   V  U   U  L      L       E
V   V  U   U  L      L       EEEE
 V V   U   U  L      L       E
  V     UUU   LLLLL  LLLLL   EEEEE"""


def render_banner(console: Console) -> None:
    logo = Text(BANNER, style="bold bright_cyan")
    title = Text(
        "PRE-DEPLOYMENT SECURITY INTELLIGENCE",
        style="bold bright_white",
        justify="center",
    )
    pipeline = Text(justify="center")
    pipeline.append("JIRA + CONFLUENCE", style="bright_blue")
    pipeline.append("  >  ", style="dim white")
    pipeline.append("RAG", style="bright_magenta")
    pipeline.append("  >  ", style="dim white")
    pipeline.append("RISK HYPOTHESES", style="bright_yellow")
    pipeline.append("  >  ", style="dim white")
    pipeline.append("TEST PLANS", style="bright_green")
    principles = Text(
        "LOCAL-FIRST  |  EVIDENCE-BOUND  |  HUMAN-REVIEWED",
        style="dim cyan",
        justify="center",
    )

    console.print(
        Panel(
            Group(Align.center(logo), Text(), title, pipeline, principles),
            border_style="bright_cyan",
            padding=(1, 2),
            width=76,
        )
    )
