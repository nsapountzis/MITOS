from flask import Flask, request
import sys, os, subprocess
from celery import Celery
import celery.signals

app = Flask(__name__)
app.config['CELERY_BROKER_URL'] = 'amqp://'
app.config['CELERY_ACCEPT_CONTENT'] = ['json']
app.config['CELERY_TASK_SERIALIZER'] = 'json'
app.config['CELERY_RESULT_SERIALIZER'] = 'json'

pubcelery = Celery(app.name, broker = app.config['CELERY_BROKER_URL'])
pubcelery.conf.update(app.config)

@pubcelery.task
def publish(recordNumber):
    subprocess.call(['sh', 'run_publish.sh', str(recordNumber)])
    #print "Hello"+str(recordNumber)

# HTTP endpoint for pinging the server
@app.route('/publisherStatus', methods=['GET'])
def is_alive():
    return "Hi, I'm the publisher and I'm alive!"

@app.route('/addToPublisher', methods=['GET'])
def update_records_set():
   r = int(request.args.get('rec'))
   publish.delay(r)
   return "True"

def main():
# Start the server on the given port else on default port
    if(len(sys.argv)==2 and argv[1] is not None):
        server_port = int(argv[1])
    else:
        server_port = 9100
    app.run(host="0.0.0.0", port=server_port, debug=True)

if __name__ == "__main__":
    main()
