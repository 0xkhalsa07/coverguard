import unittest

from _bootstrap import Event, tool_event
from coverguard.errors import InputFormatError


class EventTests(unittest.TestCase):
    def test_mcp_extraction_from_string(self):
        e = tool_event(component="acme-github-mcp", tool_name="create_issue")
        self.assertTrue(e.is_mcp)
        self.assertEqual(e.mcp_server_name, "acme-github-mcp")
        self.assertEqual(e.component, "acme-github-mcp")

    def test_builtin_has_no_mcp(self):
        e = tool_event(tool_name="Bash", mcp=False)
        self.assertFalse(e.is_mcp)
        self.assertEqual(e.component, "Bash")

    def test_flat_record_tolerated(self):
        e = Event.from_obj({"event_name": "tool_result", "tool_name": "Read",
                            "service.version": "1.1.4200"})
        self.assertEqual(e.tool_name, "Read")
        self.assertEqual(e.app_version, "1.1.4200")

    def test_non_dict_rejected(self):
        with self.assertRaises(InputFormatError):
            Event.from_obj(["not", "a", "dict"])

    def test_malformed_tool_parameters_ignored(self):
        e = Event.from_obj({"event_name": "tool_result",
                            "attributes": {"tool_parameters": "{not json"}})
        self.assertIsNone(e.mcp_server_name)


if __name__ == "__main__":
    unittest.main()
