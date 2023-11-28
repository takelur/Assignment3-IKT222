# Assignment 02 - XSS - Software Security

## Running application with Docker Compose (recommended):
```bash
$ docker compose up -d
```

## Alternatively run with Docker:
```bash
$ docker build -t blog .
$ docker run -p 5000:5000 blog
```

## Or run flask manually
```bash
$ pip install -r requirements.txt
$ cd app
$ python3 init_db.py
$ flask run --host=0.0.0.0
```