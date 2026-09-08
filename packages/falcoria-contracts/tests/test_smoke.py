def test_package_importable() -> None:
    import falcoria_contracts

    assert falcoria_contracts.__name__ == "falcoria_contracts"
