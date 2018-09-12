from flask import Flask, request
import sys, os, subprocess
from celery import Celery
import celery.signals

startTime=0
RECORD_SIZE=60
MUL=1000
URL1=''
URL2=''
runningRecords=set() 

app = Flask(__name__)
app.config['CELERY_BROKER_URL'] = 'amqp://'
app.config['CELERY_ACCEPT_CONTENT'] = ['json']
app.config['CELERY_TASK_SERIALIZER'] = 'json'
app.config['CELERY_RESULT_SERIALIZER'] = 'json'

repcelery = Celery(app.name, broker = app.config['CELERY_BROKER_URL'])
repcelery.conf.update(app.config)

@repcelery.task
def execute_task(recordNumber):
    subprocess.call(['sh', 'run_replay.sh', str(recordNumber)])

# HTTP endpoint for pinging the server
@app.route('/serverStatus', methods=['GET'])
def is_alive():
    return "Hi, I'm the replay server and I'm alive!"

'''@app.route('/registerStartTime', methods=['GET'])
def update_start_time():
   global startTime
   startTime = long(request.args.get('time'))
   print startTime
   return "True"'''

@app.route('/addToSet', methods=['GET'])
def update_records_set():
   r = int(request.args.get('rec'))
   global runningRecords
   if r not in runningRecords:
	runningRecords.add(r)
   return "True"

# HTTP endpoint for receiving the record request (timestamp (milliseconds) or a range)
@app.route('/replay', methods=['GET'])
def replay_instant():
    t1 = long(request.args.get('t1'))
    #print "Start time is "+startTime
    if 't2' in request.args:
        t2 = long(request.args.get('t2'))
        startRecNumber = int(t1/(RECORD_SIZE*MUL))
        endRecNumber = int(t2/(RECORD_SIZE*MUL))
        for i in range(startRecNumber,endRecNumber+1):
            if i not in runningRecords:
		execute_task.delay(i)		
    else:
        recNumber = int(t1/(RECORD_SIZE*MUL))
	if recNumber not in runningRecords:
	    execute_task.delay(recNumber)	        
    return "True"

def main():
# Start the server on the given port else on default port
    if(len(sys.argv)==2 and argv[1] is not None):
        server_port = int(argv[1])
    else:
        server_port = 9000
    app.run(host="0.0.0.0", port=server_port, debug=True)

if __name__ == "__main__":
    main()
