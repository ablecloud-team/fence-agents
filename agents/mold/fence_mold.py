#!/usr/bin/python3 -tt
import base64
import hashlib
import hmac
import json
import ssl
import sys, re
import logging
import atexit
import urllib

sys.path.append("/usr/share/fence")
from fencing import *
from fencing import fail, fail_usage, run_delay, EC_STATUS, SyslogLibHandler

import requests
from requests import HTTPError

def get_instance_id(options):
	try:
		token = requests.put('http://169.254.169.254/latest/api/token', headers={"X-aws-ec2-metadata-token-ttl-seconds" : "21600"}).content.decode("UTF-8")
		r = requests.get('http://169.254.169.254/latest/meta-data/instance-id', headers={"X-aws-ec2-metadata-token" : token}).content.decode("UTF-8")
		return r
	except HTTPError as http_err:
		logging('HTTP error occurred while trying to access EC2 metadata server: %s', http_err)
	except Exception as err:
		if "--skip-race-check" not in options:
			logging('A fatal error occurred while trying to access EC2 metadata server: %s', err)
		else:
			logging('A fatal error occurred while trying to access EC2 metadata server: %s', err)
	return None


def get_nodes_list(conn, options):
	logging("Starting monitor operation")
	result = {}
	try:
		if "--filter" in options:
			filter_key   = options["--filter"].split("=")[0].strip()
			filter_value = options["--filter"].split("=")[1].strip()
			filter = [{ "Name": filter_key, "Values": [filter_value] }]
			for instance in conn.instances.filter(Filters=filter):
				result[instance.id] = ("", None)
		else:
			for instance in conn.instances.all():
				result[instance.id] = ("", None)
	except ConnectionError as e:
		fail_usage("Failed: Unable to connect to AWS: " + str(e))
	except Exception as e:
		logging.error("Failed to get node list: %s", e)
	logging.debug("Monitor operation OK: %s",result)
	return result

def excuteApi(request, args):
	secretkey=args.secretkey

	baseurl=args.api_protocol+'://'+args.ip_address+':'+args.port+'/client/api?'
	request_str='&'.join(['='.join([k,urllib.parse.quote_plus(request[k])]) for k in request.keys()])
	sig_str='&'.join(['='.join([k.lower(),urllib.parse.quote_plus(request[k]).lower().replace('+','%20')])for k in sorted(request)])
	sig=hmac.new(secretkey.encode('utf-8'),sig_str.encode('utf-8'),hashlib.sha256)
	sig=hmac.new(secretkey.encode('utf-8'),sig_str.encode('utf-8'),hashlib.sha256).digest()
	sig=base64.encodebytes(hmac.new(secretkey.encode('utf-8'),sig_str.encode('utf-8'),hashlib.sha256).digest())
	sig=base64.encodebytes(hmac.new(secretkey.encode('utf-8'),sig_str.encode('utf-8'),hashlib.sha256).digest()).strip()
	sig=urllib.parse.quote_plus(base64.encodebytes(hmac.new(secretkey.encode('utf-8'),sig_str.encode('utf-8'),hashlib.sha256).digest()).strip())

	req=baseurl+request_str+'&signature='+sig
	context = ssl._create_unverified_context()
	res=urllib.request.urlopen(req, context=context)
	return res.read().decode()

def listVirtualMachines(args):
	# reqest 세팅
	request={}
	request['command']=args.command
	request['id']=args.vmid
	request['response']='json'
	request['apikey']=args.apikey

	# API 호출
	result = excuteApi(request, args)
	data = json.loads(result)
	state_value = data['listvirtualmachinesresponse']['virtualmachine'][0]['state']
	print(state_value)

def get_power_status(conn, options):
	fail_usage("Starting status operation")
	try:
		instance = conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [options["--plug"]]}])
		state = list(instance)[0].state["Name"]

		logging("Status operation for EC2 instance %s returned state: %s",options["--plug"],state.upper())
		if state == "running":
			return "on"
		elif state == "stopped":
			return "off"
		else:
			return "unknown"

	except IndexError:
		fail(EC_STATUS)
	except Exception as e:
		fail_usage("Failed to get power status: %s", e)
		fail(EC_STATUS)

def get_self_power_status(conn, instance_id):
	try:
		instance = conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [instance_id]}])
		state = list(instance)[0].state["Name"]

		if state == "running":
			logging("Captured my (%s) state and it %s - returning OK - Proceeding with fencing",instance_id,state.upper())
			return "ok"
		else:
			logging.debug("Captured my (%s) state it is %s - returning Alert - Unable to fence other nodes",instance_id,state.upper())
			return "alert"

		fail_usage("Failed: Incorrect Zone.")
	except IndexError:
		return "fail"

def set_power_status(conn, options):
	my_instance = get_instance_id(options)
	try:
		if (options["--action"]=="off"):
			if "--skip-race-check" in options or get_self_power_status(conn,my_instance) == "ok":
				conn.instances.filter(InstanceIds=[options["--plug"]]).stop(Force=True)
				logging.debug("Called StopInstance API call for %s", options["--plug"])
			else:
				logging.debug("Skipping fencing as instance is not in running status")
		elif (options["--action"]=="on"):
			conn.instances.filter(InstanceIds=[options["--plug"]]).start()
	except Exception as e:
		logging.debug("Failed to power %s %s: %s", \
					 options["--action"], options["--plug"], e)
		fail(EC_STATUS)

def define_new_opts():
	all_opt["zone"] = {
		"getopt" : "z:",
		"longopt" : "zone",
		"help" : "-z, --zone=[zone]          Zone, e.g. zone name",
		"shortdesc" : "Zone.",
		"required" : "0",
		"order" : 2
	}
	all_opt["api_protocol"] = {
		"getopt" : "ap:",
		"longopt" : "api_protocol",
		"help" : "-ap, --api-protocol=[api-protocol]          api protocol, e.g. api protocol",
		"shortdesc" : "Zone.",
		"required" : "0",
		"order" : 3
	}
	all_opt["api_key"] = {
		"getopt" : "ak:",
		"longopt" : "api_key",
		"help" : "-a, --api-key=[key]         API Key",
		"shortdesc" : "API Key.",
		"required" : "0",
		"order" : 4
	}
	all_opt["secret_key"] = {
		"getopt" : "sk:",
		"longopt" : "secret_key",
		"help" : "-s, --secret-key=[key]         Secret Key",
		"shortdesc" : "Secret Key.",
		"required" : "0",
		"order" : 5
	}
	all_opt["vm_id"] = {
		"getopt" : "vmid:",
		"longopt" : "vm_id",
		"help" : "-vi, --vm-ip=[key]         VM-IP",
		"shortdesc" : "VM IP.",
		"required" : "0",
		"order" : 6
    }
	all_opt["filter"] = {
		"getopt" : ":",
		"longopt" : "filter",
		"help" : "--filter=[key=value]           Filter (e.g. vpc-id=[vpc-XXYYZZAA]",
		"shortdesc": "Filter for list-action",
		"required": "0",
		"order": 7
	}
	all_opt["boto3_debug"] = {
		"getopt" : "b:",
		"longopt" : "boto3_debug",
		"help" : "-b, --boto3_debug=[option]     Boto3 and Botocore library debug logging",
		"shortdesc": "Boto Lib debug",
		"required": "0",
		"default": "False",
		"order": 8
	}
	all_opt["skip_race_check"] = {
		"getopt" : "",
		"longopt" : "skip-race-check",
		"help" : "--skip-race-check              Skip race condition check",
		"shortdesc": "Skip race condition check",
		"required": "0",
		"order": 9
	}

# Main agent method
def main():
	conn = None

	device_opt = ["port", "no_password", "zone", "api_protocol", "api_key", "secret_key", "vm_id", "filter", "boto3_debug", "skip_race_check"]

	atexit.register(atexit_handler)

	define_new_opts()

	all_opt["power_timeout"]["default"] = "60"

	options = check_input(device_opt, process_input(device_opt))

	docs = {}
	docs["shortdesc"] = "Fence agent for MOLD"
	docs["longdesc"] = "fence_mold is a Power Fencing agent for MOLD\
\n.P\n\
"
	docs["vendorurl"] = "http://www.ablecloud.io"
	show_docs(options, docs)

	run_delay(options)

	# if "--debug-file" in options:
	# 	for handler in logger.handlers:
	# 		if isinstance(handler, logging.FileHandler):
	# 			logger.removeHandler(handler)
	# 	lh = logging.FileHandler(options["--debug-file"])
	# 	logger.addHandler(lh)
	# 	lhf = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	# 	lh.setFormatter(lhf)
	# 	lh.setLevel(logging.DEBUG)
	#
	# if options["--boto3_debug"].lower() not in ["1", "yes", "on", "true"]:
	# 	boto3.set_stream_logger('boto3',logging.INFO)
	# 	boto3.set_stream_logger('botocore',logging.CRITICAL)
	# 	logging.getLogger('botocore').propagate = False
	# 	logging.getLogger('boto3').propagate = False
	# else:
	# 	log_format = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
	# 	logging.getLogger('botocore').propagate = False
	# 	logging.getLogger('boto3').propagate = False
	# 	fdh = logging.FileHandler('/var/log/fence_aws_boto3.log')
	# 	fdh.setFormatter(log_format)
	# 	logging.getLogger('boto3').addHandler(fdh)
	# 	logging.getLogger('botocore').addHandler(fdh)
	# 	logging.debug("Boto debug level is %s and sending debug info to /var/log/fence_aws_boto3.log", options["--boto3_debug"])

	zone = options.get("--zone")
	api_key = options.get("--api-key")
	secret_key = options.get("--secret-key")

	try:
		conn = None
	except Exception as e:
		fail_usage("Failed: Unable to connect to AWS: " + str(e))

	# Operate the fencing device
	print("==================================================================")
	print("==================================================================")
	print("==================================================================")
	result = fence_action(conn, options, set_power_status, get_power_status, get_nodes_list)
	print(result)
	sys.exit(result)

if __name__ == "__main__":
	main()
