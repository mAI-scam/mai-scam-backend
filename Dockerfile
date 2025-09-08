FROM public.ecr.aws/lambda/python:3.10

# Copy requirements.txt
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Install the specified packages
RUN pip install -r requirements.txt

# Copy all application files
COPY . ${LAMBDA_TASK_ROOT}

# Set working directory
WORKDIR ${LAMBDA_TASK_ROOT}

# Set environment variables for Lambda runtime
ENV PYTHONPATH=${LAMBDA_TASK_ROOT}

# Set the CMD to your handler
CMD [ "app.handler" ]