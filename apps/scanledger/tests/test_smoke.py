def test_package_importable() -> None:
    import falcoria_scanledger

    assert falcoria_scanledger.__name__ == "falcoria_scanledger"
