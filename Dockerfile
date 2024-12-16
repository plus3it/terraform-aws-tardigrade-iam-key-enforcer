FROM plus3it/tardigrade-ci:0.25.3

COPY ./src/python/requirements.txt /app/requirements/lambda.txt

RUN python -m pip install --no-cache-dir \
    -r /app/requirements/lambda.txt
