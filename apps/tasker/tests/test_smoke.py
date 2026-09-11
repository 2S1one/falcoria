def test_package_importable() -> None:
    import falcoria_tasker

    assert falcoria_tasker.__name__ == "falcoria_tasker"
