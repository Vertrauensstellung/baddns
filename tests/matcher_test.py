from baddns.lib.matcher import Matcher
from baddns.mock_blasthttp import MockResponse


def _response(url, status=200, body="", headers=None):
    return MockResponse(url=url, status=status, body=body, headers=headers)


def test_matcher_1():
    rules = """
identifiers:
  cnames: []
  ips: []
  nameservers: []
  not_cnames: []
matcher_rule:
  matchers:
  - dsl:
    - Host != ip
    type: dsl
  - condition: and
    part: body
    type: word
    words:
    - Domain isn't configured
    - flexbe
  - status: 404
    type: status
  matchers-condition: and
mode: http
service_name: Flexbe Subdomain Takeover
source: nucleitemplates
    """
    m = Matcher(rules)
    r = _response(
        url="https://baddns.com/test1",
        status=404,
        body="<html><p>Domain isn't configured</p><p>flexbe</p></html>",
    )
    assert m.is_match(r)


def test_matcher_2():
    rules = """
  identifiers:
    cnames: []
    ips: []
    nameservers: []
    not_cnames: []
  matcher_rule:
    matchers:
    - dsl:
      - Host != ip
      type: dsl
    - condition: and
      part: header
      type: word
      words:
      - offline.ghost.org
    - status: 302
      type: status
    matchers-condition: and
  mode: http
  service_name: ghost takeover detection
  source: nucleitemplates
    """
    m = Matcher(rules)
    r = _response(
        url="https://baddns.com/test2",
        status=302,
        body="<html><p>Content</p></html>",
        headers={"Foo": "offline.ghost.org"},
    )
    assert m.is_match(r)


def test_matcher_3():
    rules = """
  identifiers:
    cnames: []
    ips: []
    nameservers: []
    not_cnames: []
  matcher_rule:
    matchers:
    - dsl:
      - Host != ip
      type: dsl
    - regex:
      - (?:Company Not Found|you&rsquo;re looking for doesn&rsquo;t exist)
      type: regex
    matchers-condition: and
  mode: http
  service_name: worksites takeover detection
  source: nucleitemplates
        """
    m = Matcher(rules)
    r = _response(
        url="https://baddns.com/test3",
        status=302,
        body="<html><p>you&rsquo;re looking for doesn&rsquo;t exist</p></html>",
        headers={"Foo": "offline.ghost.org"},
    )
    assert m.is_match(r)


def test_matcher_4():
    rules = """
  identifiers:
    cnames: []
    ips: []
    nameservers: []
    not_cnames: []
  matcher_rule:
    matchers:
    - dsl:
      - Host != ip
      type: dsl
    - regex:
      - 'regex_matcher_test_\\d{1,4}'
      type: regex
    matchers-condition: and
  mode: http
  service_name: test signature regex
  source: nucleitemplates
        """
    m = Matcher(rules)
    r = _response(
        url="https://baddns.com/test4",
        status=302,
        body="<html><p>regex_matcher_test_1234</p></html>",
        headers={"Foo": "offline.ghost.org"},
    )
    print(m.is_match(r))
    assert m.is_match(r)
