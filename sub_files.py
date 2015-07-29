#!/usr/bin/env python
'''Take a CSV with file metadata, POST new file objects to the ENCODE DCC, upload files to the ENCODE cloud bucket'''

import os, sys, logging, urlparse, requests, csv, StringIO, re, copy, json, subprocess

logger = logging.getLogger(__name__)

EPILOG = '''Notes:

Examples:

	%(prog)s
'''

CSV_ARGS = {
		'delimiter': ',',
		'quotechar': '"',
		'quoting': csv.QUOTE_MINIMAL,
		'dialect': 'excel'
}

GET_HEADERS = {'accept': 'application/json'}
POST_HEADERS = {'accept': 'application/json', 'content-type': 'application/json'}

def get_args():
	import argparse
	parser = argparse.ArgumentParser(
		description=__doc__, epilog=EPILOG,
		formatter_class=argparse.RawDescriptionHelpFormatter)

	parser.add_argument('infile',		help='CSV file metadata to POST', nargs='?', type=argparse.FileType('rU'), default=sys.stdin)
	parser.add_argument('--outfile',	help='CSV output report', type=argparse.FileType(mode='wb',bufsize=0), default=sys.stdout)
	parser.add_argument('--debug',		help="Print debug messages", default=False, action='store_true')
	parser.add_argument('--server',		help="The server to POST to.", default=os.getenv('ENCODE_SERVER',None))
	parser.add_argument('--authid',		help="The authorization key ID for the server.", default=os.getenv('ENCODE_AUTHID',None))
	parser.add_argument('--authpw',		help="The authorization key for the server.", default=os.getenv('ENCODE_AUTHPW',None))
	parser.add_argument('--dryrun',		help="Don't POST to the database, just validate input.", default=False, action='store_true')

	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
	else: #use the defaulf logging level
		logging.basicConfig(format='%(levelname)s:%(message)s')

	if args.debug:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)

	if not args.server:
		logger.error('Server name must be specified on the command line or in environment ENCODE_SERVER')
		sys.exit(1)
	if not args.authid or not args.authpw:
		logger.error('Authorization keypair must be specified on the command line or in environment ENCODE_AUTHID, ENCODE_AUTHPW')
		sys.exit(1)

	return args

def md5(fn):
	if 'md5_command' not in globals():
		global md5_command
		if subprocess.check_output('which md5', shell=True):
			md5_command = 'md5 -q'
		elif subprocess.check_output('which md5sum', shell=True):
			md5_command = 'md5sum'
		else:
			md5_command = ''
	if not md5_command:
		logger.error("No MD5 command found (tried md5 and md5sum)")
		return None
	else:
		try:
			md5_output = subprocess.check_output(' '.join([md5_command, fn]), shell=True)
		except:
			return None
		else:
			return md5_output.partition(' ')[0].rstrip()

def test_encode_keys(server,keypair):
	test_URI = "ENCBS000AAA"
	url = urlparse.urljoin(server,test_URI)
	r = requests.get(url, auth=keypair, headers=GET_HEADERS)
	try:
		r.raise_for_status()
	except:
		logger.debug('test_encode_keys got response.txt' %(r.text))
		return False
	else:
		return True

def input_csv(fh):
	csv_args = CSV_ARGS
	input_fieldnames = csv.reader(fh, **csv_args).next()
	return csv.DictReader(fh, fieldnames=input_fieldnames, **csv_args)

def output_csv(fh,fieldnames):
	csv_args = CSV_ARGS
	additional_fields = ['accession','aws_return']
	output_fieldnames = [fn for fn in fieldnames if fn] + additional_fields
	output = csv.DictWriter(fh, fieldnames=output_fieldnames, **csv_args)
	return output

def init_csvs(in_fh,out_fh):
	input_reader = input_csv(in_fh)
	output_writer = output_csv(out_fh,input_reader.fieldnames)
	return input_reader, output_writer

def validate_file(path):
	return True

def post_file(file_metadata, server, keypair, dryrun=False):
	local_path = file_metadata.get('submitted_file_name')
	if not file_metadata.get('md5sum'):
		file_metadata['md5sum'] = md5(local_path)
	try:
		logger.debug("POST JSON: %s" %(json.dumps(file_metadata)))
	except:
		pass
	if dryrun:
		file_obj = copy.copy(file_metadata)
		file_obj.update({'accession':None})
		return file_obj
	else:
		url = urlparse.urljoin(server,'/files/')
		r = requests.post(url, auth=keypair, headers=POST_HEADERS, data=json.dumps(file_metadata))
		try:
			r.raise_for_status()
		except:
			logger.warning('POST failed: %s %s' %(r.status_code, r.reason))
			logger.warning(r.text)
			return None
		else:
			return r.json()['@graph'][0]

def upload_file(file_obj, dryrun=False):
	if dryrun:
		return None
	else:
		creds = file_obj['upload_credentials']
		logger.debug('AWS creds: %s' %(creds))
		env = os.environ.copy()
		env.update({
			'AWS_ACCESS_KEY_ID': creds['access_key'],
			'AWS_SECRET_ACCESS_KEY': creds['secret_key'],
			'AWS_SECURITY_TOKEN': creds['session_token'],
		})
		path = file_obj.get('submitted_file_name')
		try:
			subprocess.check_call(['aws', 's3', 'cp', path, creds['upload_url']], env=env)
		except subprocess.CalledProcessError as e:
			# The aws command returns a non-zero exit code on error.
			logger.error("AWS upload failed with exit code %d" %(e.returncode))
			return e.returncode
		else:
			return 0

def process_row(row):
	json_payload = {}
	for key,value in row.iteritems():
		if not key:
			continue
		try:
			json_payload.update({key:json.loads(value)})
		except:
			try:
				json_payload.update({key:json.loads('"%s"' %(value))})
			except:
				logger.warning('Could not convert field %s value %s to JSON' %(n,key,value))
				return None
	return json_payload

def main():

	args = get_args()

	server = args.server
	keypair = (args.authid, args.authpw)

	if not args.dryrun: #check ENCODE and AWS keys
		if not test_encode_keys(server, keypair):
			logger.error("Invalid ENCODE server or keys: server=%s authid=%s authpw=%s" %(args.server,args.authid,args.authpw))
			sys.exit(1)

	input_csv, output_csv = init_csvs(args.infile, args.outfile)

	output_csv.writeheader()

	for n,row in enumerate(input_csv,start=2): #row 1 is the header

		local_path = row['submitted_file_name']
		if not validate_file(local_path):
			logger.warning('Skipping row %d: file %s failed validation' %(n,local_path))
			continue

		json_payload = process_row(row)
		if not json_payload:
			logger.warning('Skipping row %d: invalid field format for JSON' %(n))
			continue

		file_object = post_file(json_payload, server, keypair, args.dryrun)
		if not file_object:
			logger.warning('Skipping row %d: POST file object failed' %(n))
			continue

		aws_return_code = upload_file(file_object, args.dryrun)
		if aws_return_code:
			logger.warning('Row %d: Non-zero AWS upload return code %d' %(aws_return_code))

		output_row = {}
		for key in output_csv.fieldnames:
			output_row.update({key:file_object.get(key)})
		output_row.update({'aws_return':aws_return_code})

		output_csv.writerow(output_row)


if __name__ == '__main__':
	main()
