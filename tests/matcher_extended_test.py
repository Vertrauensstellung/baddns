import pytest
from baddns.lib.matcher import Matcher
from baddns.mock_blasthttp import MockResponse


def _response(url="https://test.com/", status=200, body="", headers=None):
    return MockResponse(url=url, status=status, body=body, headers=headers)


class TestMatcherInit:
    def test_yaml_string(self):
        yaml_str = """
matchers-condition: and
matcher_rule:
  matchers:
  - type: word
    words: ["test"]
    part: body
"""
        m = Matcher(yaml_str)
        assert "matchers-condition" in m.rules

    def test_yaml_parse_error(self):
        with pytest.raises(ValueError, match="Error parsing YAML"):
            Matcher("{{invalid: yaml: [")

    def test_dict_input(self):
        m = Matcher({"matchers-condition": "and", "matcher_rule": {"matchers": []}})
        assert m.rules["matchers-condition"] == "and"

    def test_invalid_type(self):
        with pytest.raises(TypeError, match="yaml_rules must be a YAML string or a dict"):
            Matcher(12345)


class TestMatcherStatus:
    def test_status_negative(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "status", "status": 200, "negative": True}]},
        }
        m = Matcher(rules)
        r = _response(status=200)
        assert not m.is_match(r)

    def test_status_negative_nonmatch(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "status", "status": 200, "negative": True}]},
        }
        m = Matcher(rules)
        r = _response(status=404)
        assert m.is_match(r)


class TestMatcherWord:
    def test_word_host_part(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "host"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="body")
        assert m.is_match(r)

    def test_word_cname_part(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "cname"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="body")
        assert m.is_match(r)

    def test_word_unknown_part(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "unknown"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="body")
        with pytest.raises(ValueError, match="Unknown part"):
            m.is_match(r)

    def test_word_negative_and(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [
                    {"type": "word", "words": ["hello", "world"], "part": "body", "condition": "and", "negative": True}
                ]
            },
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello world")
        assert not m.is_match(r)

    def test_word_negative_or(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [
                    {"type": "word", "words": ["hello", "xyz"], "part": "body", "condition": "or", "negative": True}
                ]
            },
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello world")
        assert not m.is_match(r)

    def test_word_or_condition(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [{"type": "word", "words": ["hello", "notfound"], "part": "body", "condition": "or"}]
            },
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello world")
        assert m.is_match(r)


class TestMatcherRegex:
    def test_regex_header(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["abc\\d+def"], "part": "header"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="", headers={"X-Custom": "abc123def"})
        assert m.is_match(r)

    def test_regex_negative(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["abc\\d+def"], "negative": True}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="abc123def")
        assert not m.is_match(r)

    def test_regex_or_condition(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["nomatch", "hello"], "condition": "or"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello world")
        assert m.is_match(r)

    def test_regex_negative_or(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [{"type": "regex", "regex": ["hello", "nomatch"], "condition": "or", "negative": True}]
            },
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello world")
        assert not m.is_match(r)


class TestMatcherIsMatch:
    def test_or_matchers_condition(self):
        rules = {
            "matchers-condition": "or",
            "matcher_rule": {
                "matchers": [
                    {"type": "status", "status": 404},
                    {"type": "word", "words": ["hello"], "part": "body"},
                ]
            },
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello")
        assert m.is_match(r)

    def test_no_matching_func(self):
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "dsl", "dsl": ["Host != ip"]}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello")
        # dsl type has no handler, results empty, returns False
        assert not m.is_match(r)

    def test_empty_matchers(self):
        rules = {"matchers-condition": "and", "matcher_rule": {"matchers": []}}
        m = Matcher(rules)
        r = _response(status=200, body="hello")
        # empty matchers produce no results, returns False
        assert not m.is_match(r)

    def test_unknown_matchers_condition(self):
        rules = {
            "matchers-condition": "xor",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["hello"], "part": "body"}]},
        }
        m = Matcher(rules)
        r = _response(status=200, body="hello")
        assert not m.is_match(r)
