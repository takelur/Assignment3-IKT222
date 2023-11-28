FROM python:3.9-slim
WORKDIR /blog/app

# Copy the source code into the container
COPY ./app /blog/app
COPY ./db /blog/db
COPY requirements.txt /blog

RUN pip install --no-cache-dir -r /blog/requirements.txt
EXPOSE 5000

# First generate the database
RUN python init_db.py

ENTRYPOINT ["flask", "run", "--host=0.0.0.0"]