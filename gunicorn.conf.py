# gunicorn.conf.py — create tables + seed admin once, before workers fork.
# (app.py only calls init_db() under `python secure_app/app.py`.)


def on_starting(server):
    from secure_app.app import init_db
    init_db()
