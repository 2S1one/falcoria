def test_package_importable() -> None:
    import falcoria_http

    assert falcoria_http.__name__ == "falcoria_http"
