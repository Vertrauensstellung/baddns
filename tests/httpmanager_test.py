import pytest
from baddns.lib.httpmanager import headers_to_dict
from baddns.mock_blasthttp import MockBlastHTTP


def test_headers_to_dict_passes_through_dict():
    headers = {"content-type": "text/html", "x-foo": "bar"}
    assert headers_to_dict(headers) is headers


@pytest.mark.asyncio
async def test_mock_blasthttp_pops_queued_responses_in_order():
    mock = MockBlastHTTP()
    mock.add_response(url="http://example.com/", status=200, body="first")
    mock.add_response(url="http://example.com/", status=500, body="second")

    first = await mock.request("http://example.com/")
    second = await mock.request("http://example.com/")
    third = await mock.request("http://example.com/")

    assert first.status == 200 and first.body == "first"
    assert second.status == 500 and second.body == "second"
    # one response left in queue — len(queue) == 1 path returns it without popping
    assert third is second
