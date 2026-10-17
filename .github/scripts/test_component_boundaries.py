"""Keep extracted components independent from persistence and application wiring."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
INTERNAL_PREFIX = "github.com/kangheeyong/authgate/internal/"


def internal_dependencies(component):
    dependencies = set()
    for path in (ROOT / "internal" / component).glob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        source = re.sub(r"(?m)^\s*//.*$", "", path.read_text())
        declarations = re.findall(
            r'(?ms)^import\s+(?:\((.*?)\)|((?:[\w.]+\s+)?"[^"\n]+"))', source
        )
        for block, single in declarations:
            for dependency in re.findall(r'"([^"\n]+)"', block or single):
                if dependency.startswith(INTERNAL_PREFIX):
                    dependencies.add(dependency.removeprefix(INTERNAL_PREFIX))
    return dependencies


class ComponentBoundaryTests(unittest.TestCase):
    def test_signing_is_independent_of_other_internal_components(self):
        self.assertTrue((ROOT / "internal/signing/provider.go").is_file())
        self.assertEqual(internal_dependencies("signing"), set())


if __name__ == "__main__":
    unittest.main()
