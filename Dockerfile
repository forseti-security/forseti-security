FROM forseti:base_1404

# Get Forseti source code
RUN git clone --branch=dockerization_rebase https://github.com/felixbb/forseti-security.git

WORKDIR /forseti-security

RUN PYTHONPATH=. python setup.py install
RUN yes | pip uninstall forseti-security
RUN pip install mock
RUN coverage run --source='google.cloud.security' --omit='__init__.py' -m unittest discover -s . -p "*_test.py" || echo "anyway"
RUN coverage report
