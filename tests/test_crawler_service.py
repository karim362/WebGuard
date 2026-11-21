from services.crawler_service import CrawlerService


class _R:
    def __init__(self, url, status=200, text=""):
        self.url = url
        self.status_code = status
        self.headers = {"content-type": "text/html"}
        self.text = text


class _FakeHttp:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        empty = _R(url, 404, "")
        return self.pages.get(url, empty)


def test_crawler_discovers_links_and_forms():
    home_html = (
        '<a href="/about">About</a>'
        '<a href="/contact">Contact</a>'
        '<form action="/login" method="post">'
        '<input name="user"></form>'
        '<!-- secret comment -->'
    )
    home = _R("https://example.com/", text=home_html)
    about = _R("https://example.com/about", text="about")
    contact = _R("https://example.com/contact", text="c")
    http = _FakeHttp({
        "https://example.com/": home,
        "https://example.com/about": about,
        "https://example.com/contact": contact,
    })
    c = CrawlerService(http, max_pages=5, max_depth=1)
    result = c.crawl("https://example.com/")
    urls = {u.url for u in result.urls}
    assert "https://example.com/" in urls
    assert "https://example.com/about" in urls
    assert "https://example.com/contact" in urls
    assert any(f.action.endswith("/login") for f in result.forms)
    assert any("secret comment" in cm for cm in result.comments)


def test_crawler_skips_static_assets():
    home_html = (
        '<a href="/style.css">x</a>'
        '<a href="/a.png">y</a>'
        '<a href="/page">p</a>'
    )
    home = _R("https://example.com/", text=home_html)
    page = _R("https://example.com/page", text="<html>p</html>")
    http = _FakeHttp({
        "https://example.com/": home,
        "https://example.com/page": page,
    })
    c = CrawlerService(http, max_pages=5, max_depth=1)
    result = c.crawl("https://example.com/")
    urls = {u.url for u in result.urls}
    assert "https://example.com/style.css" not in urls
    assert "https://example.com/a.png" not in urls
    assert "https://example.com/page" in urls
