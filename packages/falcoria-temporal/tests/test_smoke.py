def test_package_importable() -> None:
    import falcoria_temporal

    assert falcoria_temporal.__name__ == "falcoria_temporal"
