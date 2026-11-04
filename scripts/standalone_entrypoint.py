"""PyInstaller entrypoint that delegates all runtime behavior to local_web."""

if __name__ == "__main__":
    import multiprocessing

    # PyInstaller routes frozen spawn/resource-tracker child invocations here.
    multiprocessing.freeze_support()

    from app.local_web import main

    raise SystemExit(main())
