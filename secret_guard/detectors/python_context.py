"""Conservative, local Python syntax analysis; never executes scanned code."""

import ast
import re

from secret_guard.detectors.keyword_detector import KeywordDetector


class PythonContextAnalyzer:
    """Enrich literal findings and reject expression-shaped matches in context.

    No variable resolution, import resolution or interprocedural data flow is
    attempted. Invalid/unsupported Python returns the original findings.
    """

    LOOKUPS = {"os.getenv", "os.environ.get", "environ.get", "config.get"}
    STRING_OPEN = re.compile(r"(?i)^[rub]*(\"\"\"|'''|\"|')")

    def __init__(self):
        self.keywords = KeywordDetector()

    @staticmethod
    def _name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return PythonContextAnalyzer._name(node.value) + "." + node.attr
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            return node.slice.value if isinstance(node.slice.value, str) else ""
        return ""

    def refine(self, text, findings):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return findings

        lines = text.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line))

        def position(line, byte_column):
            # AST columns count UTF-8 bytes; scanner offsets count characters.
            prefix = lines[line - 1].encode("utf-8")[:byte_column]
            return offsets[line - 1] + len(prefix.decode("utf-8"))

        def span(node):
            return (position(node.lineno, node.col_offset),
                    position(node.end_lineno, node.end_col_offset))

        def contains(outer, inner):
            return outer[0] <= inner[0] and inner[1] <= outer[1]

        def overlaps(left, right):
            return left[0] < right[1] and right[0] < left[1]

        nodes = list(ast.walk(tree))
        # Literal spans are protected: filtering a call must not hide its args.
        literals = [span(n) for n in nodes
                    if isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes))]
        literals += [span(n) for n in nodes if isinstance(n, ast.JoinedStr)]
        expression_spans = []
        additions = {}

        def sensitive(name):
            return isinstance(name, str) and self.keywords._is_secret_name(name)

        def literal(node, reason):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                return
            if len(node.value) < self.keywords.min_length:
                return
            start, end = span(node)
            segment = text[start:end]
            opening = self.STRING_OPEN.match(segment)
            # A plain single literal gets the same value offsets as Regex.
            # Escapes/adjacent strings use the complete AST source span.
            if opening:
                quote = opening.group(1)
                inner = segment[opening.end():-len(quote)]
                if inner == node.value:
                    start += opening.end()
                    end -= len(quote)
            key = (start, end, node.value)
            additions[key] = {
                "type": "Secret Keyword", "secret": node.value,
                "start": start, "end": end,
                "detector": "Python AST", "literal_value": True,
                "context_reason": reason,
            }

        def value(node, name, reason):
            if node is None or not sensitive(name):
                return
            if isinstance(node, ast.Constant):
                literal(node, reason)
            elif isinstance(node, (ast.Call, ast.Name, ast.Attribute, ast.Subscript)):
                expression_spans.append(span(node))
                # Generic calls are NOT safe: retain literal detections inside.
                # Only explicit lookup defaults acquire the surrounding context.
                if isinstance(node, ast.Call):
                    lookup(node, inherited=name)

        def lookup(node, inherited=""):
            if self._name(node.func) not in self.LOOKUPS:
                return
            key = node.args[0] if node.args else next(
                (k.value for k in node.keywords if k.arg == "key"), None)
            key_name = key.value if isinstance(key, ast.Constant) else ""
            if not (sensitive(inherited) or sensitive(key_name)):
                return
            default = node.args[1] if len(node.args) > 1 else next(
                (k.value for k in node.keywords if k.arg == "default"), None)
            if default is not None:
                literal(default, "Hardcoded default in a sensitive lookup")

        for node in nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    value(node.value, self._name(target), "Hardcoded sensitive assignment")
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                value(node.value, self._name(node.target), "Hardcoded sensitive assignment")
            elif isinstance(node, ast.Dict):
                for key, item in zip(node.keys, node.values):
                    name = key.value if isinstance(key, ast.Constant) else ""
                    value(item, name, "Hardcoded value under a sensitive dictionary key")
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    value(keyword.value, keyword.arg, "Hardcoded sensitive keyword argument")
                lookup(node)

        results = []
        for finding in findings:
            location = (finding.get("start", 0), finding.get("end", 0))
            in_literal = any(contains(s, location) for s in literals)
            # Partial matches such as 'load_password()' or 'config[' are removed
            # only inside a recognized sensitive value expression, never by line.
            if not in_literal and any(contains(s, location) for s in expression_spans):
                continue
            if not in_literal and any(overlaps(s, location) for s in expression_spans):
                # A regex can include a call prefix and part of a literal arg.
                # Keep it conservatively if it touches any literal content.
                if not any(overlaps(s, location) for s in literals):
                    continue
            result = finding.copy()
            if in_literal:
                result["literal_value"] = True
            results.append(result)
        results.extend(additions.values())
        return results
