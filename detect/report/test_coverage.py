"""Coverage RED asserts exact identities and distinguishes unassigned rules."""

import unittest

from detect.report.coverage import summarize_rules


class CoverageRedTest(unittest.TestCase):
    def test_reports_tagged_and_unassigned_rules(self):
        first = "12345678-1234-5234-9234-123456789abc"
        second = "87654321-4321-5321-8321-cba987654321"
        rules = [
            {"id": second, "title": "Key rotation action", "tags": []},
            {
                "id": first,
                "title": "Role assignment action",
                "tags": ["attack.persistence", "attack.t1098.003"],
            },
        ]
        self.assertEqual(
            summarize_rules(rules),
            {
                "rule_count": 2,
                "tagged_rule_count": 1,
                "unassigned_rule_count": 1,
                "technique_count": 1,
                "rules": [
                    {"id": first, "title": "Role assignment action", "techniques": ["T1098.003"]},
                    {"id": second, "title": "Key rotation action", "techniques": []},
                ],
                "techniques": [{"id": "T1098.003", "rule_ids": [first]}],
            },
        )


if __name__ == "__main__":
    unittest.main()
